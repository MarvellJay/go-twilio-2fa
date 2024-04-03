package main

import (
	"net/http"

	"encoding/gob"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/twilio/twilio-go"
	verify "github.com/twilio/twilio-go/rest/verify/v2"
)

var (
	// Replace "your_secret_key" with a secret key used for encryption of the session
	store            = sessions.NewCookieStore([]byte("Th!s1s_a_s3cr3t_k3y"))
	twilioAccountSID = "YOURTWILIOSID"
	twilioAuthToken  = "AUTHTOKEN"
	twilioServiceSID = "SERVICEID"
)

type User struct {
	Username     string
	Email        string
	PhoneNumber  string
	Password     string // In a real application, passwords should be hashed
	Preferred2FA string // "sms" or "email" for this example
}

// Static list of users for demonstration purposes
var users = []User{
	{
		Username:     "john_doe",
		Email:        "john@example.com",
		PhoneNumber:  "+2349036977226",
		Password:     "password123",
		Preferred2FA: "sms",
	},
	{
		Username:     "jane_doe",
		Email:        "jane@example.com",
		PhoneNumber:  "+10987654321",
		Password:     "password123",
		Preferred2FA: "email",
	},
}

func init() {
	gob.Register(User{})
}

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "signin.html", nil)
	})

	router.POST("/signin", func(c *gin.Context) {
		var loginDetails struct {
			Username string `form:"username"`
			Password string `form:"password"`
		}

		if err := c.ShouldBind(&loginDetails); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form submission"})
			return
		}

		user, authenticated := authenticateUser(loginDetails.Username, loginDetails.Password)
		if !authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
			return
		}

		// Create a session and save user details
		session, _ := store.Get(c.Request, "session_name")
		session.Values["user"] = user
		err := session.Save(c.Request, c.Writer)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session", "details": err.Error()})
			return
		}

		// Send verification code based on the preferred 2FA method
		if user.Preferred2FA == "sms" {
			err = sendVerificationCode(user.PhoneNumber)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification code", "details": err.Error()})
				return
			}
			c.Redirect(http.StatusFound, "/enter-code")
		} else {
			// Handle other 2FA methods like email here
		}
	})

	router.GET("/enter-code", func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session_name")
		user, ok := session.Values["user"].(User)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		c.HTML(http.StatusOK, "enter-code.html", gin.H{
			"Message": "A code has been sent to your number: " + user.PhoneNumber,
		})
	})

	router.POST("/verify-code", func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session_name")
		user, ok := session.Values["user"].(User)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		var form struct {
			Code string `form:"code"`
		}
		if err := c.ShouldBind(&form); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form submission"})
			return
		}

		// Verify the code with Twilio
		verified, err := verifyCodeWithTwilio(user.PhoneNumber, form.Code)
		if err != nil || !verified {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Verification failed"})
			return
		}

		// Redirect to success page or log in the user
		c.Redirect(http.StatusFound, "/success")
	})

	router.GET("/success", func(c *gin.Context) {
		session, err := store.Get(c.Request, "session_name")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve session"})
			return
		}

		user, ok := session.Values["user"].(User)
		if !ok {
			// Handle the case where the session does not exist or the user is not found
			c.Redirect(http.StatusFound, "/")
			return
		}

		c.HTML(http.StatusOK, "success.html", gin.H{
			"Username": user.Username,
		})
	})

	router.Run(":8080")
}

// authenticateUser checks if a user exists with the given username and password
func authenticateUser(username, password string) (User, bool) {
	for _, user := range users {
		if user.Username == username && user.Password == password {
			return user, true
		}
	}
	return User{}, false
}

func sendVerificationCode(phoneNumber string) error {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: twilioAccountSID,
		Password: twilioAuthToken,
	})

	params := &verify.CreateVerificationParams{}
	params.SetTo(phoneNumber)
	params.SetChannel("sms")

	_, err := client.VerifyV2.CreateVerification(twilioServiceSID, params)
	return err
}

func verifyCodeWithTwilio(phoneNumber, code string) (bool, error) {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: twilioAccountSID,
		Password: twilioAuthToken,
	})

	params := &verify.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(code)

	resp, err := client.VerifyV2.CreateVerificationCheck(twilioServiceSID, params)
	if err != nil {
		return false, err
	}

	return resp.Status != nil && *resp.Status == "approved", nil
}
