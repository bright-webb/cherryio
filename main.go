package main

import (
	// "crypto/sha256"
	"database/sql"
	// "encoding/hex"
	"encoding/json"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
	"os"
    "os/signal"
    "syscall"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	"github.com/dgrijalva/jwt-go"
)


var rateLimits = map[string]int{
	"free": 200,
	"basic": 700,
	"standard": 1500,
	"business": -1, // Unlimited
}

var (
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
)

func init() {
	var err error
	// Generate ECDSA keys
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA private key: %v", err)
	}
	publicKey = &privateKey.PublicKey
}

// Mutex for concurrency
var mutex = sync.Mutex{}

// Client represents a single WebSocket connection
type Client struct {
	conn    *websocket.Conn
	channel string
	apiKey string
	secretKey string
	userID int
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.StandardClaims
}

type Channel struct {
	clients   map[*Client]bool
	broadcast chan map[string]interface{}
	mutex     sync.Mutex
	private bool
}

// PresenceChannel extends Channel with presence tracking
type PresenceChannel struct {
	Channel
	presenceUpdates chan map[string]interface{}
}

// RateLimiter
var rateLimiters = make(map[string]*rate.Limiter)
var rateLimiterMutex sync.Mutex

var (
	db *sql.DB
	clients  = make(map[*Client]bool)
	channels = make(map[string]*PresenceChannel)
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)


// Initialize MySQL connection
func initDB(){
	cfg := mysql.Config {
		User: "root",
		Passwd: "Webilor1994@..",
		Net: "tcp",
		Addr: "44.212.55.241:3306",
		DBName: "cherryio",
		AllowNativePasswords: true,
	}
	var err error
	// dsn := "root:@tcp(127.0.0.1:3306)/cherrysocket"
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("Erroring pinging database: %v", err)
	}
}

// Validate API key and Secret key
func validateAPIKey(r *http.Request) (int, bool) {
    apiKey := r.Header.Get("X-API-KEY")
    secretKey := r.Header.Get("X-SECRET-KEY")
    if apiKey == "" || secretKey == "" {
        return 0, false
    }

	var userID int
    query := "SELECT id FROM users WHERE api_key=? AND secret_key=?"
    err := db.QueryRow(query, apiKey, secretKey).Scan(&userID)
    if err != nil {
        log.Println("Error querying database: ", err)
        return 0, false
    }

    return userID, true
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	userID, isValid := validateAPIKey(r)
	if !isValid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(privateKey) // Sign with ECDSA private key

	if err != nil {
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"token": tokenString}
	json.NewEncoder(w).Encode(response)
}

func handleAuthError(w http.ResponseWriter, err error) {
    if err == sql.ErrNoRows {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        log.Println("No matching user found")
    } else {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        log.Printf("Error querying database: %v", err)
    }
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate token signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil 
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check token expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, fmt.Errorf("token has expired")
			}
		} else {
			return nil, fmt.Errorf("invalid exp claim")
		}

		// Check user id claim
		if _, ok := claims["user_id"].(float64); !ok {
			return nil, fmt.Errorf("invalid or missing user_id claim")
		}

		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}



func generateKeys(user string) (string, string, error){
	apiKey := generateRandomString(32)
	secretKey := generateRandomString(64)

	// Save to database
	_, err := db.Exec("INSERT INTO users (user, api_key, secret_key) VALUES(?, ?, ?)", user, apiKey, secretKey)
	if err != nil{
		return "", "", err
	}
	return apiKey, secretKey, nil
}

func createKeysHandler(w http.ResponseWriter, r *http.Request){
	var req map[string]string
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println("Error decoding request body: ", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user := req["user"]

	apiKey := generateRandomString(32)
	secretKey := generateRandomString(64)

	log.Println("API Key generate: ", apiKey)
	log.Println("Secret Key generate: ", secretKey)

	query := "INSERT INTO users (user, api_key, secret_key) VALUES(?, ?, ?)"
	_, err = db.Exec(query, user, apiKey, secretKey)
	
	if err != nil {
		log.Println("Error inserting data: ", err)
		http.Error(w, "Not working", http.StatusInternalServerError)
		return
	}

	log.Println("Successfully inserted data")

	resp := map[string]string{
		"api_key": apiKey,
		"secret_key": secretKey,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func getKeysHandler(w http.ResponseWriter, r *http.Request){
	user := r.URL.Query().Get("user")

	var apiKey, secretKey string
	err := db.QueryRow("SELECT api_key, secret_key FROM users WHERE user =?", user).Scan(&apiKey, &secretKey)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	resp := map[string]string{
		"api_key": apiKey,
		"secret_key": secretKey,
	}
	json.NewEncoder(w).Encode(resp)
}


// Regenerate api and secret keys
func regenerateKeysHandler(w http.ResponseWriter, r *http.Request){
	user := r.URL.Query().Get("user")

	apiKey := generateRandomString(32)
	secretKey := generateRandomString(64)
	_, err := db.Exec("UPDATE users SET api_key =?, secret_key = ? WHERE user = ?", apiKey, secretKey, user)
	if err != nil {
		http.Error(w, "Failed to regenerate keys", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"api_key": apiKey,
		"secret_key": secretKey,
	}
	json.NewEncoder(w).Encode(resp)
}
// Check if user has reached the rate limit
func checkRateLimit(apiKey, userTier string) bool {
	mutex.Lock()
	defer mutex.Unlock()

	// Calculate today's date
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// Count connections made today
	var connectionCount int
	query := "SELECT COUNT(*) FROM connections WHERE api_key=? AND connected_at >= ?"
	err := db.QueryRow(query, apiKey, startOfDay).Scan(&connectionCount)

	if err != nil {
		log.Println("Error querying database: ", err)
		return false
	}

	limit := rateLimits[userTier]
	if limit == -1 {
		return true
	}

	return connectionCount < limit
}
// Middleware for rate limiting
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-KEY")
		// fmt.Println("From middleware");

		// Initialize rate limiter for the API key if not already present
		rateLimiterMutex.Lock()
		if _, exists := rateLimiters[apiKey]; !exists {
			rateLimiters[apiKey] = rate.NewLimiter(1, 5) // 1 request per second, burst if 5
		}
		limiter := rateLimiters[apiKey]
		rateLimiterMutex.Unlock()

		// Check if the request is within the rate limit
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}



// Handle WebSocket connection
func handleConnections(w http.ResponseWriter, r *http.Request) {	
	var userID int
	var userTier string
	var connectionsToday int
	var err error

	// Check for API Keys
	apiKey := r.Header.Get("X-API-KEY")
	secretKey := r.Header.Get("X-SECRET-KEY")

	if apiKey != "" && secretKey != "" {
		err := db.QueryRow("SELECT id, user_tier, connections_today FROM users WHERE api_key=? AND secret_key=?", apiKey, secretKey).Scan(&userID, &userTier, &connectionsToday)
		if err != nil {
			handleAuthError(w, err)
			return
		}
	} else {
		// Using token
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "No authentication provide", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(token)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		userId, ok := claims["user_id"].(float64)

		if !ok {
			http.Error(w, "Invalid user ID in token ", http.StatusUnauthorized)
			return
		}

		userID = int(userId)

		err = db.QueryRow("SELECT user_tier, connections_today FROM users WHERE id = ?", 
                          userID).Scan(&userTier, &connectionsToday)
        if err != nil {
            handleAuthError(w, err)
            return
        }
	}

	

	// Rate limiting based on user tier
	maxConnections := 0
	switch userTier {
	case "free":
		maxConnections = 200
	case "basic":
		maxConnections = 700
	case "standard":
		maxConnections = 1500
	case "business":
		maxConnections = -1 // unlimited
	}

	if maxConnections != -1 && connectionsToday >= maxConnections {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error during WebSocket upgrade:", err)
		return
	}
	defer ws.Close()

	// Increment connectionsToday
	connectionsToday++

	// Update the users table
	update := "UPDATE users SET connections_today = ? WHERE api_key = ?"
	_, err = db.Exec(update, connectionsToday, apiKey)
	if err != nil {
		log.Println("Error updating connections_today:", err)
		
		return
	}

	// Track the connection in the connections table
	query := "INSERT INTO connections (api_key) VALUES (?)"
	_, err = db.Exec(query, apiKey)
	if err != nil {
		log.Println("Error inserting into connections:", err)
		return
	}


	client := &Client{conn: ws, userID: userID}

	mutex.Lock()
	clients[client] = true
	mutex.Unlock()

	for {
		var msg map[string]interface{}
		err := ws.ReadJSON(&msg)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}

		if action, ok := msg["action"].(string); ok && action == "subscribe" {
			if channelName, ok := msg["channel"].(string); ok {
				subscribeToChannel(client, channelName, r)
			}
			continue
		}

		if client.channel != "" {
			broadcastMessage(client.channel, msg)
		}
	}

	disconnectClient(client)

	// Clean up 
	defer func(){
		query := "DELETE FROM connections WHERE api_key=? ORDER BY connected_at DESC LIMIT 1"
		_, err := db.Exec(query, apiKey)
		if err != nil {
			log.Println("Error deleting connection: ", err)
		}
	}()

}

// Get current connections
func getCurrentConnections(w http.ResponseWriter, r *http.Request){
	apiKey := r.Header.Get("X-API-KEY")
	
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE api_key = ? ", apiKey).Scan(userID)
	if err != nil{
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	connections := 0
	mutex.Lock()

	for client := range clients {
		if client.userID == userID {
			connections++
		}
	}
	mutex.Unlock()
	resp := map[string]int{"current_connections": connections}
	json.NewEncoder(w).Encode(resp)
	
}

func getConnectedClients(w http.ResponseWriter, r *http.Request){
	channelName := r.URL.Query().Get("channel")

	channel, ok := channels[channelName]
	if !ok {
		http.Error(w, "channel not found", http.StatusNotFound)
		return
	}

	clientList := []string{}
	channel.mutex.Lock()
	for client := range channel.clients {
		clientList = append(clientList, fmt.Sprintf("client %d", client.userID))
	}

	channel.mutex.Unlock()

	resp := map[string][]string{"connected_clients": clientList}
	json.NewEncoder(w).Encode(resp)
}

// Subscribe a client to a channel
func subscribeToChannel(client *Client, channelName string, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()
	

	if _, ok := channels[channelName]; !ok {
		channels[channelName] = &PresenceChannel{
			Channel: Channel{
				clients:   make(map[*Client]bool),
				broadcast: make(chan map[string]interface{}),
				private: false,
			},
			presenceUpdates: make(chan map[string]interface{}),
		}

	}

	presenceChannel := channels[channelName]

	if presenceChannel.private {
		_, isValid := validateAPIKey(r)
		if !isValid {
			log.Println("Unauthorized access to private channel ", channelName)
			client.conn.WriteJSON(map[string]interface{}{
				"error": "Unauthorized access to private channel",
			})
			return
		}

	}
	presenceChannel.mutex.Lock()
	defer presenceChannel.mutex.Unlock()

	client.channel = channelName
	presenceChannel.clients[client] = true

	presenceUpdate := map[string]interface{}{
		"event":   "presence_update",
		"channel": channelName,
		"clients": len(presenceChannel.clients),
	}

	for c := range presenceChannel.clients {
		err := c.conn.WriteJSON(presenceUpdate)
		if err != nil {
			log.Printf("Error sending presence update to client: %v", err)
			c.conn.Close()
			disconnectClient(c)
		}
	}

	fmt.Printf("Client subscribed to channel: %s\n", channelName)
}


// Broadcast a message to all clients in a channel
func broadcastMessage(channelName string, message map[string]interface{}) {
	
	mutex.Lock()
	presenceChannel, ok := channels[channelName]
	mutex.Unlock()

	if !ok {
		return
	}

	if _, ok := message["event"]; !ok {
		log.Println("Error: message does not contain an event")
		return
	}

	presenceChannel.mutex.Lock()
	defer presenceChannel.mutex.Unlock()

	for client := range presenceChannel.clients {
		err := client.conn.WriteJSON(message)
		if err != nil {
			log.Printf("Error broadcasting to client: %v", err)
			client.conn.Close()
			disconnectClient(client)
		}
	}
}

func Broadcast(w http.ResponseWriter, r *http.Request){
	_, isValid := validateAPIKey(r)

	if !isValid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Channel string                 `json:"channel"`
		Event   string                 `json:"event"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	
	broadcastMessage(req.Channel, map[string]interface{}{
		"event": req.Event,
		"data":  req.Data,
	})

	w.WriteHeader(http.StatusOK)
}

// Handle client disconnection
func disconnectClient(client *Client) {
	mutex.Lock()
	defer mutex.Unlock()

	if client.channel != "" {
		presenceChannel := channels[client.channel]
		presenceChannel.mutex.Lock()
		defer presenceChannel.mutex.Unlock()

		delete(presenceChannel.clients, client)

		presenceUpdate := map[string]interface{}{
			"event":   "presence_update",
			"channel": client.channel,
			"clients": len(presenceChannel.clients),
		}

		for c := range presenceChannel.clients {
			err := c.conn.WriteJSON(presenceUpdate)
			if err != nil {
				log.Printf("Error sending presence update to client: %v", err)
				c.conn.Close()
				disconnectClient(c)
			}
		}

		if len(presenceChannel.clients) == 0 {
			delete(channels, client.channel)
		}
	}

	delete(clients, client)
	fmt.Println("Client disconnected")
}

func resetConnectionsDaily(db *sql.DB) {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()

    for {
        <-ticker.C
        resetConnections(db)
    }
}

func resetConnections(db *sql.DB) {
    query := "UPDATE users SET connections_today = 0"
    _, err := db.Exec(query)
    if err != nil {
        log.Println("Error resetting connections today:", err)
    } else {
        log.Println("connections_today has been reset.")
    }
}

func main() {
	go resetConnectionsDaily(db)
	initDB()
	defer db.Close()


	r := mux.NewRouter()


	r.HandleFunc("/keys", createKeysHandler).Methods("POST")
	r.HandleFunc("/keys", getKeysHandler).Methods("GET")
	r.HandleFunc("/keys/regenerate", regenerateKeysHandler).Methods("PUT")
	r.HandleFunc("/current-connections", getCurrentConnections).Methods("GET")
	r.HandleFunc("/clients", getConnectedClients).Methods("GET")
	r.HandleFunc("/publish", Broadcast).Methods("POST")
	r.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request){
		w.Write([]byte("Hello world"));
	}).Methods("GET")
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
	})
	r.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
        // Set CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*") 
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS") 
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Secret-Key, X-Api-Key")
        w.Header().Set("Access-Control-Allow-Credentials", "true") 

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        handleAuth(w, r)
        // w.Write([]byte("Authenticated"))
    })
	r.HandleFunc("/ws", handleConnections)
	
	
	r.Use(rateLimitMiddleware)
	

	srv := &http.Server{
		Handler: r,
		Addr: "0.0.0.0:6001",
		WriteTimeout: 15 * time.Second,
		ReadTimeout: 15 * time.Second,
	}

	fmt.Println("Starting Websocket server server on port 6001")
	log.Fatal(srv.ListenAndServe())

	// log.Println("WebSocket server started on :6001")
	// err := http.ListenAndServe(":6001", r)
	// if err != nil {
	// 	log.Fatal("ListenAndServe: ", err)
	// }

	 // Signal handling
	 quit := make(chan os.Signal, 1)
	 signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	 <-quit
 
	 // Graceful shutdown logic here...
	 os.Exit(0)
}

func generateRandomString(n int) string {
	const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = characters[rand.Intn(len(characters))]
	}
	return string(b)
}
