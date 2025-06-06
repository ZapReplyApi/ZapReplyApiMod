package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/sirupsen/logrus"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/appstate"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

type ExtractedMedia struct {
	MediaPath string `json:"media_path"`
	MimeType  string `json:"mime_type"`
	Caption   string `json:"caption"`
}

type evtReaction struct {
	ID      string `json:"id,omitempty"`
	Message string `json:"message,omitempty"`
}

type evtMessage struct {
	ID            string `json:"id,omitempty"`
	Text          string `json:"text,omitempty"`
	RepliedId     string `json:"replied_id,omitempty"`
	QuotedMessage string `json:"quoted_message,omitempty"`
}

var (
	cli           *whatsmeow.Client
	log           waLog.Logger
	historySyncID int32
	startupTime   = time.Now().Unix()
)

func InitWaDB(ctx context.Context) *sqlstore.Container {
	log = waLog.Stdout("Main", config.WhatsappLogLevel, true)
	dbLog := waLog.Stdout("Database", config.WhatsappLogLevel, true)

	storeContainer, err := initDatabase(ctx, dbLog)
	if err != nil {
		log.Errorf("Database initialization error: %v", err)
		panic(pkgError.InternalServerError(fmt.Sprintf("Database initialization error: %v", err)))
	}

	return storeContainer
}

func initDatabase(ctx context.Context, dbLog waLog.Logger) (*sqlstore.Container, error) {
	if strings.HasPrefix(config.DBURI, "file:") {
		return sqlstore.New(ctx, "sqlite3", config.DBURI, dbLog)
	} else if strings.HasPrefix(config.DBURI, "postgres:") {
		return sqlstore.New(ctx, "postgres", config.DBURI, dbLog)
	}

	return nil, fmt.Errorf("unknown database type: %s. Only sqlite3 and postgres supported", config.DBURI)
}

func InitWaCLI(ctx context.Context, storeContainer *sqlstore.Container) *whatsmeow.Client {
	device, err := storeContainer.GetFirstDevice(ctx)
	if err != nil {
		log.Errorf("Failed to get device: %v", err)
		panic(err)
	}

	if device == nil {
		log.Errorf("No device found")
		panic("No device found")
	}

	osName := fmt.Sprintf("%s %s", config.AppOs, config.AppVersion)
	store.DeviceProps.PlatformType = &config.AppPlatform
	store.DeviceProps.Os = &osName

	cli = whatsmeow.NewClient(device, waLog.Stdout("Client", config.WhatsappLogLevel, true))
	cli.EnableAutoReconnect = true
	cli.AutoTrustIdentity = true
	cli.AddEventHandler(func(rawEvt interface{}) {
		handler(ctx, rawEvt)
	})

	return cli
}

func GetWaCli() *whatsmeow.Client {
	return cli
}

func GetGroupName(ctx context.Context, jid types.JID) (string, error) {
	if !strings.Contains(jid.String(), "@g.us") {
		return "", nil
	}
	groupInfo, err := cli.GetGroupInfo(jid)
	if err != nil {
		return "", fmt.Errorf("failed to get group info: %v", err)
	}
	return groupInfo.GroupName.Name, nil
}

func handler(ctx context.Context, rawEvt interface{}) {
	switch evt := rawEvt.(type) {
	case *events.DeleteForMe:
		handleDeleteForMe(ctx, evt)
	case *events.AppStateSyncComplete:
		handleAppStateSyncComplete(ctx, evt)
	case *events.PairSuccess:
		handlePairSuccess(ctx, evt)
	case *events.LoggedOut:
		handleLoggedOut(ctx)
	case *events.Connected, *events.PushNameSetting:
		handleConnected(ctx)
	case *events.StreamReplaced:
		handleStreamReplaced(ctx)
	case *events.Message:
		handleMessage(ctx, evt)
	case *events.Receipt:
		handleReceipt(ctx, evt)
	case *events.HistorySync:
		handleHistorySync(ctx, evt)
	case *events.AppState:
		handleAppState(ctx, evt)
	case *events.CallOffer:
		handleCallOffer(ctx, evt)
	}
}

func handleDeleteForMe(_ context.Context, evt *events.DeleteForMe) {
	log.Infof("Deleted message %s for %s", evt.MessageID, evt.SenderJID.String())
}

func handleAppStateSyncComplete(_ context.Context, evt *events.AppStateSyncComplete) {
	if len(cli.Store.PushName) > 0 && evt.Name == appstate.WAPatchCriticalBlock {
		if err := cli.SendPresence(types.PresenceAvailable); err != nil {
			log.Warnf("Failed to send available presence: %v", err)
		} else {
			log.Infof("Marked self as available")
		}
	}
}

func handlePairSuccess(_ context.Context, evt *events.PairSuccess) {
	log.Infof("Successfully paired with %s", evt.ID.String())
}

func handleLoggedOut(_ context.Context) {
	log.Infof("Logged out")
}

func handleConnected(_ context.Context) {
	if len(cli.Store.PushName) == 0 {
		return
	}

	if err := cli.SendPresence(types.PresenceAvailable); err != nil {
		log.Warnf("Failed to send available presence: %v", err)
	} else {
		log.Infof("Marked self as available")
	}
}

func handleStreamReplaced(_ context.Context) {
	os.Exit(0)
}

func handleMessage(ctx context.Context, evt *events.Message) {
	metaParts := buildMessageMetaParts(evt)
	log.Infof("Received message %s from %s (%s): %+v",
		evt.Info.ID,
		evt.Info.SourceString(),
		strings.Join(metaParts, ", "),
		evt.Message,
	)

	message := ExtractMessageText(evt)
	utils.RecordMessage(evt.Info.ID, evt.Info.Sender.String(), message)

	handleImageMessage(ctx, evt)
	handleAutoReply(evt)
	handleWebhookForward(ctx, evt)
}

func handleCallOffer(ctx context.Context, evt *events.CallOffer) {
	log.Infof("Received call offer %s from %s", evt.CallID, evt.From.String())
	if len(config.WhatsappWebhook) > 0 {
		go func() {
			payload := map[string]interface{}{
				"from":      evt.From.String(),
				"call_id":   evt.CallID,
				"type":      "call_received",
				"status":    "received",
				"timestamp": evt.Timestamp.Format(time.RFC3339),
				"IsGroup":   false,
			}
			for _, url := range config.WhatsappWebhook {
				if err := SubmitWebhook(payload, url); err != nil {
					logrus.Errorf("Failed to send call webhook: %v", err)
				}
			}
		}()
	}
}

func buildMessageMetaParts(evt *events.Message) []string {
	metaParts := []string{
		fmt.Sprintf("pushname: %s", evt.Info.PushName),
		fmt.Sprintf("timestamp: %s", evt.Info.Timestamp),
	}
	if evt.Info.Type != "" {
		metaParts = append(metaParts, fmt.Sprintf("type: %s", evt.Info.Type))
	}
	if evt.Info.Category != "" {
		metaParts = append(metaParts, fmt.Sprintf("category: %s", evt.Info.Category))
	}
	if evt.IsViewOnce {
		metaParts = append(metaParts, "view once")
	}
	return metaParts
}

func handleImageMessage(ctx context.Context, evt *events.Message) {
	if img := evt.Message.GetImageMessage(); img != nil {
		if path, err := ExtractMedia(ctx, config.PathStorages, img); err != nil {
			log.Errorf("Failed to download image: %v", err)
		} else {
			log.Infof("Image downloaded to %s", path)
		}
	}
}

func handleAutoReply(evt *events.Message) {
	if config.WhatsappAutoReplyMessage != "" &&
		!strings.Contains(evt.Info.Chat.String(), "@g.us") &&
		!evt.Info.IsIncomingBroadcast() &&
		evt.Message.GetExtendedTextMessage().GetText() != "" {
		_, _ = cli.SendMessage(
			context.Background(),
			FormatJID(evt.Info.Sender.String()),
			&waE2E.Message{Conversation: proto.String(config.WhatsappAutoReplyMessage)},
		)
	}
}

func handleWebhookForward(ctx context.Context, evt *events.Message) {
	if len(config.WhatsappWebhook) > 0 &&
		!strings.Contains(evt.Info.SourceString(), "broadcast") {
		go func(evt *events.Message) {
			if err := forwardToWebhook(ctx, evt); err != nil {
				logrus.Error("Failed forward to webhook: ", err)
			}
		}(evt)
	}
}

func handleReceipt(_ context.Context, evt *events.Receipt) {
	if evt.Type == types.ReceiptTypeRead || evt.Type == types.ReceiptTypeReadSelf {
		log.Infof("%v was read by %s at %s", evt.MessageIDs, evt.SourceString(), evt.Timestamp)
	} else if evt.Type == types.ReceiptTypeDelivered {
		log.Infof("%s was delivered to %s at %s", evt.MessageIDs[0], evt.SourceString(), evt.Timestamp)
	}
}

func handleHistorySync(_ context.Context, evt *events.HistorySync) {
	id := atomic.AddInt32(&historySyncID, 1)
	fileName := fmt.Sprintf("%s/history-%d-%s-%d-%s.json",
		config.PathStorages,
		startupTime,
		cli.Store.ID.String(),
		id,
		evt.Data.SyncType.String(),
	)

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Errorf("Failed to open file to write history sync: %v", err)
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err = enc.Encode(evt.Data); err != nil {
		log.Errorf("Failed to write history sync: %v", err)
		return
	}

	log.Infof("Wrote history sync to %s", fileName)
}

func handleAppState(ctx context.Context, evt *events.AppState) {
	log.Debugf("App state event: %+v / %+v", evt.Index, evt.SyncActionValue)
}

func buildEventMessage(evt *events.Message) evtMessage {
	message := evtMessage{
		Text: evt.Message.GetConversation(),
		ID:   evt.Info.ID,
	}

	if extendedMessage := evt.Message.GetExtendedTextMessage(); extendedMessage != nil {
		message.Text = extendedMessage.GetText()
		message.RepliedId = extendedMessage.ContextInfo.GetStanzaID()
		message.QuotedMessage = extendedMessage.ContextInfo.GetQuotedMessage().GetConversation()
	} else if protocolMessage := evt.Message.GetProtocolMessage(); protocolMessage != nil {
		if editedMessage := protocolMessage.GetEditedMessage(); editedMessage != nil {
			if extendedText := editedMessage.GetExtendedTextMessage(); extendedText != nil {
				message.Text = extendedText.GetText()
				message.RepliedId = extendedText.ContextInfo.GetStanzaID()
				message.QuotedMessage = extendedText.ContextInfo.GetQuotedMessage().GetConversation()
			}
		}
	}
	return message
}

func buildEventReaction(evt *events.Message) evtReaction {
	var waReaction evtReaction
	if reactionMessage := evt.Message.GetReactionMessage(); reactionMessage != nil {
		waReaction.Message = reactionMessage.GetText()
		waReaction.ID = reactionMessage.GetKey().GetID()
	}
	return waReaction
}

func buildForwarded(evt *events.Message) bool {
	if extendedText := evt.Message.GetExtendedTextMessage(); extendedText != nil {
		return extendedText.ContextInfo.GetIsForwarded()
	} else if protocolMessage := evt.Message.GetProtocolMessage(); protocolMessage != nil {
		if editedMessage := protocolMessage.GetEditedMessage(); editedMessage != nil {
			if extendedText := editedMessage.GetExtendedTextMessage(); extendedText != nil {
				return extendedText.ContextInfo.GetIsForwarded()
			}
		}
	}
	return false
}
