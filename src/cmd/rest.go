package cmd

import (
    "fmt"
    "log"
    "net/http"
    "strconv"
    "strings"

    "github.com/aldinokemal/go-whatsapp-web-multidevice/config"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/helpers"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/middleware"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/websocket"
    "github.com/dustin/go-humanize"
    "github.com/gofiber/adaptor/v2"
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/basicauth"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/filesystem"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/gofiber/template/html/v2"
    "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"
)

var restCmd = &cobra.Command{
    Use:   "rest",
    Short: "Enviar API do WhatsApp via HTTP",
    Long:  `Esta aplicação é um clone de https://github.com/aldinokemal/go-whatsapp-web-multidevice`,
    Run:   restServer,
}

func init() {
    rootCmd.AddCommand(restCmd)
}

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
                log.Fatalln("Autenticação básica inválida, use o formato <user>:<secret>")
            }
            account[ba[0]] = ba[1]
        }

        app.Use(basicauth.New(basicauth.Config{
            Users: account,
        }))
    }

    rest.InitRestApp(app, appUsecase)
    rest.InitRestSend(app, sendUsecase)
    rest.InitRestUser(app, userUsecase)
    rest.InitRestMessage(app, messageUsecase)
    rest.InitRestGroup(app, groupUsecase)
    rest.InitRestNewsletter(app, newsletterUsecase)

    app.Post("/send-presence", adaptor.HTTPHandlerFunc(whatsapp.SendPresenceHandler))
    app.Post("/end-call", adaptor.HTTPHandlerFunc(whatsapp.EndCallHandler))
    app.Post("/call-ended", adaptor.HTTPHandlerFunc(whatsapp.EndCallHandler))

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

    if err := app.Listen(":" + strconv.Itoa(int(config.AppPort))); err != nil {
        logrus.Error("Falha ao iniciar servidor: ", err.Error())
    }
}
