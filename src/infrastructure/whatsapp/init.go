package whatsapp

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "regexp"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/aldinokemal/go-whatsapp-web-multidevice/config"
    pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
    "github.com/aldinokemal/go-whatsapp-web-multidevice/ui/websocket"
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
    ID            string      `json:"id,omitempty"`
    Text          string      `json:"text,omitempty"`
    RepliedId     string      `json:"replied_id,omitempty"`
    QuotedMessage string      `json:"quoted_message,omitempty"`
    Type          string      `json:"type"`
    Poll          *evtPoll    `json:"poll,omitempty"`
}

type evtPoll struct {
    Title          string   `json:"title"`
    Options        []string `json:"options"`
    SelectedOption string   `json:"selected_option"`
}

type evtCall struct {
    ID           string `json:"id,omitempty"`
    Type         string `json:"type,omitempty"`
    Status       string `json:"status,omitempty"`
    Timestamp    int64  `json:"timestamp,omitempty"`
    CallerNumber string `json:"caller_number,omitempty"`
}

var (
    cli           *whatsmeow.Client
    log           waLog.Logger
    historySyncID int32
    startupTime   = time.Now().Unix()
    urlRegex      = regexp.MustCompile(`https?://[^\s]+|www\.`)

    callJIDs      = make(map[string]types.JID)
    callJIDsMutex sync.Mutex

    // Cache para enquetes
    pollCache     = make(map[string]*waE2E.PollCreationMessage)
    pollCacheMutex sync.Mutex
)

func InitWaDB(ctx context.Context) *sqlstore.Container {
    log = waLog.Stdout("Main", config.WhatsappLogLevel, true)
    dbLog := waLog.Stdout("Database", config.WhatsappLogLevel, true)

    storeContainer, err := initDatabase(ctx, dbLog)
    if err != nil {
        log.Errorf("Erro ao inicializar banco de dados: %v", err)
        panic(pkgError.InternalServerError(fmt.Sprintf("Erro ao inicializar banco de dados: %v", err)))
    }

    return storeContainer
}

func initDatabase(ctx context.Context, dbLog waLog.Logger) (*sqlstore.Container, error) {
    if strings.HasPrefix(config.DBURI, "file:") {
        return sqlstore.New(ctx, "sqlite3", config.DBURI, dbLog)
    } else if strings.HasPrefix(config.DBURI, "postgres:") {
        return sqlstore.New(ctx, "postgres", config.DBURI, dbLog)
    }

    return nil, fmt.Errorf("tipo de banco de dados desconhecido: %s. Atualmente apenas sqlite3(file:) e postgres são suportados", config.DBURI)
}

func InitWaCLI(ctx context.Context, storeContainer *sqlstore.Container) *whatsmeow.Client {
    device, err := storeContainer.GetFirstDevice(ctx)
    if err != nil {
        log.Errorf("Falha ao obter dispositivo: %v", err)
        panic(err)
    }

    if device == nil {
        log.Errorf("Nenhum dispositivo encontrado")
        panic("Nenhum dispositivo encontrado")
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

    // Limpar pollCache no início para evitar dados antigos
    pollCacheMutex.Lock()
    pollCache = make(map[string]*waE2E.PollCreationMessage)
    pollCacheMutex.Unlock()
    logrus.Debugf("pollCache limpo no início")

    return cli
}

func handler(ctx context.Context, rawEvt interface{}) {
    switch evt := rawEvt.(type) {
    case *events.DeleteForMe:
        handleDeleteForMe(ctx, evt)
    case *events.AppStateSyncComplete:
        handleAppStateSyncComplete(evt)
    case *events.PairSuccess:
        handlePairSuccess(evt)
    case *events.LoggedOut:
        handleLoggedOut()
    case *events.Connected, *events.PushNameSetting:
        handleConnectionEvents()
    case *events.StreamReplaced:
        handleStreamReplaced()
    case *events.Message:
        handleMessage(ctx, evt)
    case *events.Receipt:
        handleReceipt(ctx, evt)
    case *events.Presence:
        handlePresence(ctx, evt)
    case *events.HistorySync:
        handleHistorySync(ctx, evt)
    case *events.AppState:
        handleAppState(ctx, evt)
    case *events.CallOffer:
        handleCallOffer(ctx, evt)
    case *events.CallTerminate:
        handleCallTerminate(ctx, evt)
    }
}

func handleDeleteForMe(_ context.Context, evt *events.DeleteForMe) {
    logrus.Infof("Mensagem apagada %s para %s", evt.MessageID, evt.SenderJID.String())
}

func handleAppStateSyncComplete(evt *events.AppStateSyncComplete) {
    if len(cli.Store.PushName) > 0 && evt.Name == appstate.WAPatchCriticalBlock {
        if err := cli.SendPresence(types.PresenceAvailable); err != nil {
            log.Warnf("Falha ao enviar presença disponível: %v", err)
        } else {
            logrus.Infof("Marcado como disponível")
        }
    }
}

func handlePairSuccess(evt *events.PairSuccess) {
    websocket.Broadcast <- websocket.BroadcastMessage{
        Code:    "LOGIN_SUCCESS",
        Message: fmt.Sprintf("Pareado com sucesso com %s", evt.ID.String()),
    }
}

func handleLoggedOut() {
    websocket.Broadcast <- websocket.BroadcastMessage{
        Code:   "LIST_DEVICES",
        Result: nil,
    }
}

func handleConnectionEvents() {
    if len(cli.Store.PushName) == 0 {
        return
    }

    if err := cli.SendPresence(types.PresenceAvailable); err != nil {
        log.Warnf("Falha ao enviar presença disponível: %v", err)
    } else {
        logrus.Infof("Marcado como disponível")
    }
}

func handleStreamReplaced() {
    os.Exit(0)
}

func handleCallOffer(ctx context.Context, evt *events.CallOffer) {
    logrus.Infof("Oferta de chamada recebida: ID=%s, From=%s, Timestamp=%s",
        evt.CallID, evt.From.String(), evt.Timestamp)

    callJIDsMutex.Lock()
    callJIDs[evt.CallID] = evt.From
    callJIDsMutex.Unlock()

    if len(config.WhatsappWebhook) > 0 {
        isGroup := IsGroupJid(evt.From.String())
        var groupName string
        if isGroup {
            if groupInfo, err := cli.GetGroupInfo(evt.From); err != nil {
                logrus.Errorf("Falha ao obter informações do grupo para %s: %v", evt.From.String(), err)
            } else {
                groupName = groupInfo.GroupName.Name
            }
        }

        data := evtCall{
            ID:           evt.CallID,
            Type:         "unknown",
            Status:       "received",
            Timestamp:    evt.Timestamp.Unix(),
            CallerNumber: evt.From.String(),
        }

        logrus.Debugf("Dados do webhook para oferta de chamada: %+v", data)

        if err := forwardToWebhook(ctx, nil, evtMessage{Type: "call"}, false, isGroup, groupName, data); err != nil {
            logrus.Errorf("Falha ao encaminhar oferta de chamada para webhook: %v", err)
        }
    }
}

func handleCallTerminate(ctx context.Context, evt *events.CallTerminate) {
    logrus.Infof("Término de chamada recebido: ID=%s, From=%s, Reason=%s, Timestamp=%s",
        evt.CallID, evt.From.String(), evt.Reason, evt.Timestamp)

    if len(config.WhatsappWebhook) > 0 {
        isGroup := IsGroupJid(evt.From.String())
        var groupName string
        if isGroup {
            if groupInfo, err := cli.GetGroupInfo(evt.From); err != nil {
                logrus.Errorf("Falha ao obter informações do grupo para %s: %v", evt.From.String(), err)
            } else {
                groupName = groupInfo.GroupName.Name
            }
        }

        data := evtCall{
            ID:           evt.CallID,
            Type:         "unknown",
            Status:       "rejected",
            Timestamp:    evt.Timestamp.Unix(),
            CallerNumber: evt.From.String(),
        }

        logrus.Debugf("Dados do webhook para término de chamada: %+v", data)

        if err := forwardToWebhook(ctx, nil, evtMessage{Type: "call"}, false, isGroup, groupName, data); err != nil {
            logrus.Errorf("Falha ao encaminhar término de chamada para webhook: %v", err)
        }
    }

    go func(callID string) {
        time.Sleep(5 * time.Second)
        callJIDsMutex.Lock()
        delete(callJIDs, callID)
        callJIDsMutex.Unlock()
        logrus.Debugf("call_id %s removido do mapa após atraso", callID)
    }(evt.CallID)
}

func handleMessage(ctx context.Context, evt *events.Message) {
    if reaction := evt.Message.GetReactionMessage(); reaction != nil {
        logrus.Infof("Reação recebida para mensagem %s de %s: %s",
            reaction.GetKey().GetID(),
            evt.Info.Sender.String(),
            reaction.GetText(),
        )

        if len(config.WhatsappWebhook) > 0 {
            isGroup := IsGroupJid(evt.Info.Chat.String())
            var groupName string
            if isGroup {
                if groupInfo, err := cli.GetGroupInfo(evt.Info.Chat); err != nil {
                    logrus.Errorf("Falha ao obter informações do grupo para %s: %v", evt.Info.Chat.String(), err)
                } else {
                    groupName = groupInfo.GroupName.Name
                }
            }

            isMyNumber := evt.Info.IsFromMe

            data := evtReaction{
                ID:   reaction.GetKey().GetID(),
                Message: reaction.GetText(),
            }

            logrus.Debugf("Dados do webhook para reação: %+v", data)

            if err := forwardToWebhook(ctx, evt, evtMessage{Type: "reaction"}, isMyNumber, isGroup, groupName, evtCall{}); err != nil {
                logrus.Errorf("Falha ao encaminhar reação para webhook: %v", err)
            }
        }
        return
    }

    metaParts := buildMessageMetaParts(evt)
    logrus.Infof("Mensagem recebida %s de %s (%s): %+v",
        evt.Info.ID,
        evt.Info.SourceString(),
        strings.Join(metaParts, ", "),
        evt.Message,
    )

    // Armazenar enquete no cache
    if pollCreation := evt.Message.GetPollCreationMessage(); pollCreation != nil {
        pollCacheMutex.Lock()
        // Usar o ID da mensagem de criação como chave
        pollID := evt.Info.ID
        pollCache[pollID] = pollCreation
        pollCacheMutex.Unlock()
        logrus.Debugf("Enquete armazenada no cache: ID=%s, Título=%s, Opções=%v, MessageID=%s, From=%s", pollID, pollCreation.GetName(), extractPollOptions(pollCreation), evt.Info.ID, evt.Info.SourceString())
    }

    RecordMessage(evt.Info.ID, evt.Info.Sender.String(), ExtractMessageText(evt))

    handleImageMessage(ctx, evt)
    handleAutoReply(evt)
    handleWebhookForward(ctx, evt)
}

func extractPollOptions(poll *waE2E.PollCreationMessage) []string {
    var options []string
    for _, opt := range poll.GetOptions() {
        options = append(options, opt.GetOptionName())
    }
    return options
}

func buildMessageMetaParts(evt *events.Message) []string {
    metaParts := []string{
        fmt.Sprintf("pushname: %s", evt.Info.PushName),
        fmt.Sprintf("timestamp: %v", evt.Info.Timestamp),
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
            logrus.Errorf("Falha ao baixar imagem: %v", err)
        } else {
            logrus.Infof("Imagem baixada para %s", path)
        }
    }
}

func handleAutoReply(evt *events.Message) {
    if config.WhatsappAutoReplyMessage != "" &&
        !IsGroupJid(evt.Info.Chat.String()) &&
        !evt.Info.IsIncomingBroadcast() &&
        evt.Message.GetExtendedTextMessage().GetText() != "" {
        _, _ = cli.SendMessage(
            context.Background(),
            FormatJID(evt.Info.Sender.String()),
            &waE2E.Message{Conversation: proto.String(config.WhatsappAutoReplyMessage)},
        )
    }
}

func processPoll(ctx context.Context, evt *events.Message) (*evtPoll, error) {
    pollUpdate := evt.Message.GetPollUpdateMessage()
    if pollUpdate == nil {
        return nil, nil
    }

    pollKey := pollUpdate.GetPollCreationMessageKey()
    if pollKey == nil {
        logrus.Errorf("Chave da enquete original ausente para mensagem %s", evt.Info.ID)
        return nil, fmt.Errorf("chave da enquete original ausente")
    }

    creationID := pollKey.GetID()
    logrus.Debugf("Processando enquete com creationID=%s para mensagem %s, From=%s", creationID, evt.Info.ID, evt.Info.SourceString())

    // Consultar cache para título e opções
    pollCacheMutex.Lock()
    pollCreation, exists := pollCache[creationID]
    pollCacheMutex.Unlock()

    title := ""
    var options []string
    if exists {
        title = pollCreation.GetName()
        for _, opt := range pollCreation.GetOptions() {
            options = append(options, opt.GetOptionName())
        }
        logrus.Debugf("Enquete encontrada no cache: ID=%s, Título=%s, Opções=%v", creationID, title, options)
    } else {
        logrus.Warnf("Enquete original %s não encontrada no cache para mensagem %s", creationID, evt.Info.ID)
        // Logar o conteúdo atual do cache para depuração
        pollCacheMutex.Lock()
        logrus.Debugf("Conteúdo atual do pollCache: %+v", pollCache)
        pollCacheMutex.Unlock()
        return nil, fmt.Errorf("enquete original não encontrada")
    }

    // Tentar capturar a opção selecionada
    selectedOption := ""
    vote := pollUpdate.GetVote()
    if vote != nil {
        logrus.Debugf("Voto encontrado para enquete %s: EncPayload=%v", creationID, vote.GetEncPayload())
        // Devido à criptografia, não podemos descriptografar diretamente
        logrus.Warnf("Descriptografia de voto não suportada, selected_option será vazio")
    } else {
        logrus.Warnf("Nenhuma informação de voto encontrada para enquete %s", creationID)
    }

    return &evtPoll{
        Title:          title,
        Options:        options,
        SelectedOption: selectedOption,
    }, nil
}

func handleWebhookForward(ctx context.Context, evt *events.Message) {
    if len(config.WhatsappWebhook) > 0 &&
        !strings.Contains(evt.Info.SourceString(), "broadcast") {
        go func(evt *events.Message) {
            isGroup := IsGroupJid(evt.Info.Chat.String())
            var groupName string
            if isGroup {
                if groupInfo, err := cli.GetGroupInfo(evt.Info.Chat); err != nil {
                    logrus.Errorf("Falha ao obter informações do grupo para %s: %v", evt.Info.Chat.String(), err)
                } else {
                    groupName = groupInfo.GroupName.Name
                }
            }

            msgType := determineMessageType(evt.Message)
            logrus.Debugf("Tipo de mensagem determinado: %s para mensagem ID: %s", msgType, evt.Info.ID)

            isMyNumber := evt.Info.IsFromMe

            data := evtMessage{
                ID:            evt.Info.ID,
                Text:          ExtractMessageText(evt),
                RepliedId:     extractRepliedId(evt),
                QuotedMessage: extractQuotedMessage(evt),
                Type:          msgType,
            }

            if msgType == "poll" {
                if pollData, err := processPoll(ctx, evt); err != nil {
                    logrus.Errorf("Erro ao processar enquete para mensagem %s: %v", evt.Info.ID, err)
                } else if pollData != nil {
                    data.Poll = pollData
                }
            }

            logrus.Debugf("Dados do webhook: %+v", data)

            if err := forwardToWebhook(ctx, evt, data, isMyNumber, isGroup, groupName, evtCall{}); err != nil {
                logrus.Errorf("Falha ao encaminhar para webhook: %v", err)
            }
        }(evt)
    }
}

func determineMessageType(msg *waE2E.Message) string {
    if msg == nil {
        return "unknown"
    }

    if msg.GetPollCreationMessage() != nil || msg.GetPollUpdateMessage() != nil || msg.GetPollCreationMessageV3() != nil {
        return "poll"
    }

    if conversation := msg.GetConversation(); conversation != "" {
        if urlRegex.MatchString(conversation) {
            return "link"
        }
        return "text"
    }
    if extended := msg.GetExtendedTextMessage(); extended != nil {
        if text := extended.GetText(); text != "" {
            if urlRegex.Match([]byte(text)) {
                return "link"
            }
            return "text"
        }
    }

    if msg.GetImageMessage() != nil {
        return "image"
    }
    if msg.GetAudioMessage() != nil {
        return "audio"
    }
    if msg.GetVideoMessage() != nil {
        return "video"
    }
    if msg.GetDocumentMessage() != nil {
        return "document"
    }
    if msg.GetStickerMessage() != nil {
        return "sticker"
    }
    if msg.GetContactMessage() != nil {
        return "contact"
    }
    if msg.GetLocationMessage() != nil {
        return "location"
    }
    if msg.GetButtonsMessage() != nil || msg.GetTemplateMessage() != nil {
        return "interactive"
    }
    return "unknown"
}

func extractRepliedId(evt *events.Message) string {
    if evt.Message == nil {
        return ""
    }
    if extended := evt.Message.GetExtendedTextMessage(); extended != nil {
        if extended.ContextInfo != nil {
            return extended.GetContextInfo().GetStanzaId()
        }
    }
    return ""
}

func extractQuotedMessage(evt *events.Message) string {
    if evt.Message == nil {
        return ""
    }
    if extended := evt.Message.GetExtendedTextMessage(); extended != nil {
        if extended.ContextInfo != nil {
            if quoted := extended.GetContextInfo().GetQuotedMessage(); quoted != nil {
                if quotedConversation := quoted.GetConversation(); quotedConversation != "" {
                    return quotedConversation
                }
                if quotedExtended := quoted.GetExtendedTextMessage(); quotedExtended != nil {
                    return quotedExtended.GetText()
                }
            }
        }
    }
    return ""
}

func handleReceipt(_ context.Context, evt *events.Receipt) {
    if evt.Type == types.ReceiptTypeRead || evt.Type == types.ReceiptTypeReadSelf {
        logrus.Infof("%v foi lido por %s em %s", evt.MessageIDs, evt.SourceString(), evt.Timestamp)
    } else if evt.Type == types.ReceiptTypeDelivered {
        logrus.Infof("%s foi entregue para %s em %s", evt.MessageIDs[0], evt.SourceString(), evt.Timestamp)
    }
}

func handlePresence(_ context.Context, evt *events.Presence) {
    if evt.Unavailable {
        if evt.LastSeen.IsZero() {
            logrus.Infof("%s está offline agora", evt.From)
        } else {
            logrus.Infof("%s está offline agora (visto pela última vez: %s)", evt.From, evt.LastSeen)
        }
    } else {
        logrus.Infof("%s está online agora", evt.From)
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

    file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0644)
    if err != nil {
        logrus.Errorf("Erro ao abrir arquivo para escrever sincronização: %v", err)
        return
    }
    defer file.Close()

    enc := json.NewEncoder(file)
    enc.SetIndent("", "  ")
    if err = enc.Encode(evt.Data); err != nil {
        logrus.Errorf("Erro ao escrever sincronização de histórico: %v", err)
        return
    }

    logrus.Infof("Histórico sincronizado registrado em %s", fileName)
}

func handleAppState(ctx context.Context, evt *events.AppState) {
    logrus.Debugf("Evento de estado do app: %+v / %+v", evt.Index, evt.SyncActionValue)
}
