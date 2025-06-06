package cmd

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/helpers"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/middleware"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/websocket"
	"github.com/dustin/go-humanize"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.mau.fi/whatsmeow/types"
)

var restCmd = &cobra.Command{
	Use:   "rest",
	Short: "Send whatsapp API over http",
	Long:  `This application is from clone https://github.com/aldinokemal/go-whatsapp-web-multidevice`,
	Run:   restServer,
}

func init() {
	rootCmd.AddCommand(restCmd)
}

var (
	// Cache para evitar múltiplos webhooks para o mesmo call_id e JID
	callWebhookCache = sync.Map{}
	cacheTTL         = 5 * time.Minute
)

func restServer(_ *cobra.Command, _ []string) {
	err := utils.CreateFolder(config.PathQrCode, config.PathSendItems, config.PathStorages, config.PathMedia)
	if err != nil {
		log.Fatalln(err)
	}

	engine := html.NewFileSystem(http.FS(EmbedIndex), ".html")
	engine.AddFunc("isEnableBasicAuth", func(token any) bool {
		return token != nil
	})
	app := fiber.New(fiber.Config{
		Views:     engine,
		BodyLimit: int(config.WhatsappSettingMaxVideoSize),
	})

	app.Static("/statics", "./statics")
	app.Use("/components", filesystem.New(filesystem.Config{
		Root:       http.FS(EmbedViews),
		PathPrefix: "views/components",
		Browse:     true,
	}))
	app.Use("/assets", filesystem.New(filesystem.Config{
		Root:       http.FS(EmbedViews),
		PathPrefix: "views/assets",
		Browse:     true,
	}))

	app.Use(middleware.Recovery())
	app.Use(middleware.BasicAuth())
	if config.AppDebug {
		app.Use(logger.New())
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	if len(config.AppBasicAuthCredential) > 0 {
		account := make(map[string]string)
		for _, basicAuth := range config.AppBasicAuthCredential {
			ba := strings.Split(basicAuth, ":")
			if len(ba) != 2 {
				log.Fatalln("Basic auth is not valid, please this following format <user>:<secret>")
			}
			account[ba[0]] = ba[1]
		}

		app.Use(basicauth.New(basicauth.Config{
			Users: account,
		}))
	}

	app.Post("/send-presence", func(c *fiber.Ctx) error {
		var request struct {
			JID      string `json:"jid"`
			Presence string `json:"presence"`
			Duration int64  `json:"duration"`
		}
		if err := c.BodyParser(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}

		if request.JID == "" || request.Presence == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "jid and presence are required"})
		}

		waCli := whatsapp.GetWaCli()
		if waCli == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "WhatsApp client not initialized"})
		}

		jid, err := whatsapp.ParseJID(request.JID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Invalid JID: %v", err)})
		}

		var presence types.ChatPresence
		var media types.ChatPresenceMedia
		switch request.Presence {
		case "typing":
			presence = types.ChatPresenceComposing
			media = types.ChatPresenceMediaText
		case "recording":
			presence = types.ChatPresenceComposing
			media = types.ChatPresenceMediaAudio
		default:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid presence type, must be 'typing' or 'recording'"})
		}

		err = waCli.SendChatPresence(jid, presence, media)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Failed to send presence: %v", err)})
		}

		if request.Duration > 0 {
			go func() {
				time.Sleep(time.Duration(request.Duration) * time.Second)
				if err := waCli.SendChatPresence(jid, types.ChatPresencePaused, types.ChatPresenceMediaText); err != nil {
					logrus.Errorf("Failed to send paused presence: %v", err)
				}
			}()
		}

		return c.JSON(fiber.Map{"status": fmt.Sprintf("Presence %s sent to %s", request.Presence, request.JID)})
	})

	app.Post("/call-ended", func(c *fiber.Ctx) error {
		var request struct {
			CallID string `json:"call_id"`
			JID    string `json:"jid"`
		}
		if err := c.BodyParser(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}

		if request.CallID == "" || request.JID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "call_id and jid are required"})
		}

		waCli := whatsapp.GetWaCli()
		if waCli == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "WhatsApp client not initialized"})
		}

		jid, err := whatsapp.ParseJID(request.JID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Invalid JID: %v", err)})
		}

		// Chave única para cache
		cacheKey := request.CallID + ":" + request.JID
		// Verifica se já foi processado
		if _, exists := callWebhookCache.LoadOrStore(cacheKey, time.Now()); exists {
			logrus.Infof("Webhook para call_id %s e JID %s já enviado, ignorando", request.CallID, request.JID)
			return c.JSON(fiber.Map{
				"status":  "call rejected (already processed)",
				"call_id": request.CallID,
				"jid":     request.JID,
			})
		}

		// Expira a entrada após cacheTTL
		go func() {
			time.Sleep(cacheTTL)
			callWebhookCache.Delete(cacheKey)
		}()

		err = waCli.RejectCall(jid, request.CallID)
		if err != nil {
			callWebhookCache.Delete(cacheKey) // Remove da cache em caso de erro
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Failed to reject call: %v", err)})
		}

		if len(config.WhatsappWebhook) > 0 {
			go func() {
				payload := map[string]interface{}{
					"from":      request.JID,
					"call_id":   request.CallID,
					"type":      "call_received",
					"status":    "rejected",
					"timestamp": time.Now().Format(time.RFC3339),
					"IsGroup":   false,
				}
				for _, url := range config.WhatsappWebhook {
					if err := whatsapp.SubmitWebhook(payload, url); err != nil {
						logrus.Errorf("Failed to send call rejected webhook: %v", err)
					}
				}
			}()
		}

		return c.JSON(fiber.Map{
			"status":  "call rejected",
			"call_id": request.CallID,
			"jid":     request.JID,
		})
	})

	rest.InitRestApp(app, appUsecase)
	rest.InitRestSend(app, sendUsecase)
	rest.InitRestUser(app, userUsecase)
	rest.InitRestMessage(app, messageUsecase)
	rest.InitRestGroup(app, groupUsecase)
	rest.InitRestNewsletter(app, newsletterUsecase)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("views/index", fiber.Map{
			"AppHost":        fmt.Sprintf("%s://%s", c.Protocol(), c.Hostname()),
			"AppVersion":     config.AppVersion,
			"BasicAuthToken": c.UserContext().Value(middleware.AuthorizationValue("BASIC_AUTH")),
			"MaxFileSize":    humanize.Bytes(uint64(config.WhatsappSettingMaxFileSize)),
			"MaxVideoSize":   humanize.Bytes(uint64(config.WhatsappSettingMaxVideoSize)),
		})
	})

	websocket.RegisterRoutes(app, appUsecase)
	go websocket.RunHub()

	go helpers.SetAutoConnectAfterBooting(appUsecase)
	go helpers.SetAutoReconnectChecking(whatsappCli)
	if config.WhatsappChatStorage {
		go helpers.StartAutoFlushChatStorage()
	}

	if err = app.Listen(":" + config.AppPort); err != nil {
		log.Fatalln("Failed to start: ", err.Error())
	}
}
