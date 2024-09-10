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
	"strconv"
	"time"
	"os"
    "os/signal"
    "syscall"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	"github.com/dgrijalva/jwt-go"
	 "github.com/go-redis/redis/v8"
    "context"
)

var (
	db *sql.DB
	clients  = make(map[*Client]bool)
	connectedClient = make(map[int]*Client)
	channels = make(map[string]*PresenceChannel)
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	userChannels = make(map[int]string)
	idCount int;
)

var websocketClients = make(map[*websocket.Conn]bool)
var redisClient *redis.Client

var (
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
)

var ctx = context.Background()

// Initialize Redis client
var rdb = redis.NewClient(&redis.Options{
    Addr: "localhost:6379", 
})

type UserCache struct {
    UserID           int    `json:"user_id"`
    UserTier         string `json:"user_tier"`
    ConnectionsToday int    `json:"connections_today"`
}

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
	id int
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
	pubsub           *redis.PubSub
}

// RateLimiter
var rateLimiters = make(map[string]*rate.Limiter)
var rateLimiterMutex sync.Mutex



// Initialize MySQL connection
func initDB(){
	cfg := mysql.Config {
		User: "root",
		Passwd: "",
		Net: "tcp",
		Addr: "127.0.0.1:3306",
		DBName: "cherrysocket",
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

func cacheAPIKey(apiKey string, secret string) {
    // Cache the secret with an expiration time (e.g., 1 hour)
    err := redisClient.Set(ctx, "api_key:"+apiKey, secret, time.Hour).Err()
    if err != nil {
        log.Printf("Error caching API key: %v", err)
    }
}

func getAPIKeyFromCache(apiKey string) (string, bool) {
    secret, err := redisClient.Get(ctx, "api_key:"+apiKey).Result()
    if err == redis.Nil {
        return "", false // key not found
    } else if err != nil {
        log.Printf("Error getting API key from Redis: %v", err)
        return "", false
    }

    return secret, true
}

// Add user to a presence channel
func addUserToPresenceChannel(userID, channelName string) {
    err := redisClient.SAdd(ctx, "presence:"+channelName, userID).Err()
    if err != nil {
        log.Printf("Error adding user to presence channel: %v", err)
    }
}

// Remove user from a presence channel
func removeUserFromPresenceChannel(userID, channelName string) {
    err := redisClient.SRem(ctx, "presence:"+channelName, userID).Err()
    if err != nil {
        log.Printf("Error removing user from presence channel: %v", err)
    }
}

// Get all users in a presence channel
func getUsersInPresenceChannel(channelName string) ([]string, error) {
    users, err := redisClient.SMembers(ctx, "presence:"+channelName).Result()
    if err != nil {
        return nil, err
    }
    return users, nil
}


func validateAPIKey(r *http.Request) (int, bool) {
    apiKey := r.Header.Get("X-API-KEY")
    secretKey := r.Header.Get("X-SECRET-KEY")
    if apiKey == "" || secretKey == "" {
        return 0, false
    }

    // Check Redis cache
    cacheKey := "auth:" + apiKey + ":" + secretKey
    cachedUserID, err := rdb.Get(ctx, cacheKey).Result()
    if err == nil {
        // Cache hit, return the cached user ID
        userID, err := strconv.Atoi(cachedUserID)
        if err == nil {
            return userID, true
        }
    }

    // Cache miss, query the database
    var userID int
    query := "SELECT id FROM users WHERE api_key=? AND secret_key=?"
    err = db.QueryRow(query, apiKey, secretKey).Scan(&userID)
    if err != nil {
        log.Println("Error querying database: ", err)
        return 0, false
    }

    // Store the result in Redis
    err = rdb.Set(ctx, cacheKey, userID, 0).Err()
    if err != nil {
        log.Println("Error setting cache: ", err)
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
	tokenString, err := token.SignedString(privateKey)

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

func handleRedisMessages(channelName string) {
    pubsub := rdb.Subscribe(ctx, channelName)
    defer pubsub.Close()

    ch := pubsub.Channel()

    for msg := range ch {
        var message map[string]interface{}
        if err := json.Unmarshal([]byte(msg.Payload), &message); err != nil {
            log.Printf("Error unmarshalling message: %v", err)
            continue
        }

        // Broadcast to all clients in the channel
        if channel, ok := channels[channelName]; ok {
            channel.mutex.Lock()
            for client := range channel.clients {
                if client.conn != nil {
                    if err := client.conn.WriteJSON(message); err != nil {
                        log.Printf("Error sending message to client %d: %v", client.userID, err)
                    }
                }
            }
            channel.mutex.Unlock()
        }
    }
}


func broadcastToClients(channelName string, message map[string]interface{}) {
    mutex.Lock()
    presenceChannel, ok := channels[channelName]
    mutex.Unlock()

    if !ok {
        log.Printf("Channel %s not found", channelName)
        return
    }

    presenceChannel.mutex.Lock()
    defer presenceChannel.mutex.Unlock()

    for client := range presenceChannel.clients {
        err := client.conn.WriteJSON(message)
        if err != nil {
            log.Printf("Error sending message to client %d: %v", client.userID, err)
            client.conn.Close()
            delete(presenceChannel.clients, client)
        }
    }
}


func broadcastMessageToRedis(channelName string, message map[string]interface{}) {
    jsonMessage, err := json.Marshal(message)
    if err != nil {
        log.Printf("Error marshaling message: %v", err)
        return
    }

    err = redisClient.Publish(context.Background(), channelName, jsonMessage).Err()
    if err != nil {
        log.Printf("Error publishing message to Redis: %v", err)
    } else {
        log.Printf("Message published to Redis channel: %s", channelName)
    }
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

// Middleware for rate limiting
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-KEY")
		// fmt.Println("From middleware");

		// Initialize rate limiter for the API key if not already present
		rateLimiterMutex.Lock()
		if _, exists := rateLimiters[apiKey]; !exists {
			rateLimiters[apiKey] = rate.NewLimiter(1, 10) // 1 request per second, burst if 5
		}
		limiter := rateLimiters[apiKey]
		rateLimiterMutex.Unlock()

		// Check if the request is within the rate limit
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"message": "Rate limit exceeded"})
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
    
    cacheKey := ""

    if apiKey != "" && secretKey != "" {
        cacheKey = "user:" + apiKey + ":" + secretKey
    } else {
        // Using token
        token := r.URL.Query().Get("token")
        if token == "" {
            http.Error(w, "No authentication provided", http.StatusUnauthorized)
            return
        }

        claims, err := validateToken(token)
        if err != nil {
            http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
            return
        }

        userId, ok := claims["user_id"].(float64)
        if !ok {
            http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
            return
        }

        userID = int(userId)
        cacheKey = "user:" + strconv.Itoa(userID)
    }

    // Check Redis cache
    cachedData, err := rdb.Get(ctx, cacheKey).Result()
    if err == redis.Nil {
        // Cache miss, query the database
        if apiKey != "" && secretKey != "" {
            err := db.QueryRow("SELECT id, user_tier, connections_today FROM users WHERE api_key=? AND secret_key=?", apiKey, secretKey).Scan(&userID, &userTier, &connectionsToday)
            if err != nil {
                handleAuthError(w, err)
                return
            }
        } else {
            err = db.QueryRow("SELECT user_tier, connections_today FROM users WHERE id = ?", userID).Scan(&userTier, &connectionsToday)
            if err != nil {
                handleAuthError(w, err)
                return
            }
        }

        // Cache the result in Redis
        userCache := UserCache{
            UserID:           userID,
            UserTier:         userTier,
            ConnectionsToday: connectionsToday,
        }
        cacheData, _ := json.Marshal(userCache)
        err = rdb.Set(ctx, cacheKey, cacheData, time.Minute*10).Err() // Cache for 10 minutes
        if err != nil {
            log.Println("Error setting cache: ", err)
        }
    } else if err == nil {
        // Cache hit, use cached data
        var userCache UserCache
        err := json.Unmarshal([]byte(cachedData), &userCache)
        if err != nil {
            log.Println("Error unmarshalling cache: ", err)
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }
        userID = userCache.UserID
        userTier = userCache.UserTier
        connectionsToday = userCache.ConnectionsToday
    } else {
        log.Println("Error retrieving cache: ", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
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
		json.NewEncoder(w).Encode(map[string]string{"message": "Rate limit exceeded"})
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
    update := "UPDATE users SET connections_today = ? WHERE id = ?"
    _, err = db.Exec(update, connectionsToday, userID)
    if err != nil {
        log.Println("Error updating connections_today:", err)
        return
    }

    // Update the cache with the new connections count
    userCache := UserCache{
        UserID:           userID,
        UserTier:         userTier,
        ConnectionsToday: connectionsToday,
    }
    cacheData, _ := json.Marshal(userCache)
    err = rdb.Set(ctx, cacheKey, cacheData, time.Minute*5).Err()
    if err != nil {
        log.Println("Error updating cache: ", err)
    }

    // Track the connection in the connections table
    query := "INSERT INTO connections (user_id) VALUES (?)"
    _, err = db.Exec(query, userID)
    if err != nil {
        log.Println("Error inserting into connections:", err)
        return
    }

	idCount++
	clientID := idCount
    client := &Client{conn: ws, id: clientID}
	connectedClient[clientID] = client
	

    mutex.Lock()
    // Check if user was previously subscribed
    if channel, ok := userChannels[clientID]; ok {
        client.channel = channel
        subscribeToChannel(client, channel, r)
    } else {
        client.channel = ""
    }
    // Mark the user as connected
    clients[client] = true
    mutex.Unlock()

    log.Printf("New WebSocket connection established for user %d", userID)
	

    for {
        var msg map[string]interface{}
        err := ws.ReadJSON(&msg)
        if err != nil {
            log.Printf("Error reading message: %v", err)
            break
        }
        if action, ok := msg["action"].(string); ok {
            switch action {
            case "subscribe":
                if channelName, ok := msg["channel"].(string); ok {
                    subscribeToChannel(client, channelName, r)
                }
            case "unsubscribe":
                if channelName, ok := msg["channel"].(string); ok {
                    unsubscribeFromChannel(client, channelName)
                }
            default:
                fmt.Println("Nothing to do here");
            }
        }
    }

    disconnectClient(client)

    // Clean up
    defer func() {
        query := "DELETE FROM connections WHERE user_id=? ORDER BY connected_at DESC LIMIT 1"
		update := "UPDATE users SET user_tier = ? WHERE id =?";
		db.Exec(update, userTier, userID)
        _, err := db.Exec(query, userID)
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
		clientList = append(clientList, fmt.Sprintf("client %d", client.id))
	}

	channel.mutex.Unlock()

	resp := map[string][]string{"connected_clients": clientList}
	json.NewEncoder(w).Encode(resp)
}

// Subscribe a client to a channel
func subscribeToChannel(client *Client, channelName string, r *http.Request) {
    mutex.Lock()
    defer mutex.Unlock()
	if currentChannel, ok := userChannels[client.id]; ok && currentChannel == channelName {
		log.Printf("Already subscribed to this channel with user id %d", userChannels[client.id])
        return
    }
    log.Printf("Subscribing client %d to channel: %s", client.id, channelName)
    
    client.channel = channelName
    userChannels[client.id] = channelName


    if _, ok := channels[channelName]; !ok {
        channels[channelName] = &PresenceChannel{
            Channel: Channel{
                clients:   make(map[*Client]bool),
                broadcast: make(chan map[string]interface{}),
                private:   false,
            },
            presenceUpdates: make(chan map[string]interface{}),
        }
        go handleRedisMessages(channelName)
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

    presenceChannel.clients[client] = true

    presenceUpdate := map[string]interface{}{
        "event":   "presence_update",
        "channel": channelName,
        "clients": len(presenceChannel.clients),
    }
    broadcastMessageToRedis(channelName, presenceUpdate)

    log.Printf("Client %d subscribed to channel: %s\n", client.id, channelName)
}



// Unscribe from channel
func unsubscribeFromChannel(client *Client, channelName string) {
    if channel, ok := channels[channelName]; ok {
        channel.mutex.Lock()
        defer channel.mutex.Unlock()
		client.channel = channelName
		userChannels[client.id] = ""
		log.Printf("Already subscribed to this %s", channelName)
        delete(channel.clients, client)

        if len(channel.clients) == 0 {
            log.Printf("No more clients in channel %s. Unsubscribing from Redis.", channelName)
            delete(clients, client)
        }

		log.Printf("Still subscribed to %s?", channelName)

        log.Printf("Client %d unsubscribed from channel: %s", client.id, channelName)
    }
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

	message := map[string]interface{}{
        "event": req.Event,
        "data":  req.Data,
    }
	// broadcastMessage(req.Channel, map[string]interface{}{
	// 	"event": req.Event,
	// 	"data":  req.Data,
	// })
	broadcastMessageToRedis(req.Channel, message)

	w.WriteHeader(http.StatusOK)
}

// Handle client disconnection
func disconnectClient(client *Client) {
    log.Printf("Client %d disconnected from channel: %s", client.id, client.channel)

    channelName := client.channel

    if channelName != "" {
        unsubscribeFromChannel(client, channelName)
    }

    // Clean up the client's connection
    client.conn.Close()

    // Remove client from the clients map
    mutex.Lock()
    delete(clients, client)
    mutex.Unlock()

    log.Printf("Client %d fully disconnected", client.id)
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
	redisClient = redis.NewClient(&redis.Options{
        Addr:     "localhost:6379", // Replace with your Redis server address
        Password: "",               // No password set
        DB:       0,                // Use default DB
    })
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

func generateUserID() int {
    rand.Seed(time.Now().UnixNano())
    return rand.Int()
}