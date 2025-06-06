package whatsapp

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/aldinokemal/go-whatsapp-web-multidevice/config"
    pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
    "github.com/sirupsen/logrus"
    "go.mau.fi/whatsmeow/types"
    "go.mau.fi/whatsmeow/types/events"
)

func forwardToWebhook(ctx context.Context, evt *events.Message, data evtMessage, isMyNumber bool, isGroup bool, groupName string, callData evtCall) error {
    logrus.Info("Encaminhando evento para webhook:", config.WhatsappWebhook)
    payload, err := createPayload(ctx, evt, data, isMyNumber, isGroup, groupName, callData)
    if err != nil {
        return err
    }

    logrus.Debugf("Payload do webhook: %+v", payload)

    for _, url := range config.WhatsappWebhook {
        if err = submitWebhook(payload, url); err != nil {
            return err
        }
    }

    logrus.Info("Evento encaminhado para o webhook")
    return nil
}

func createPayload(ctx context.Context, evt *events.Message, data evtMessage, isMyNumber bool, isGroup bool, groupName string, callData evtCall) (map[string]interface{}, error) {
    body := make(map[string]interface{})

    if data.Type == "call" {
        body["call"] = map[string]interface{}{
            "id":            callData.ID,
            "type":          callData.Type,
            "status":        callData.Status,
            "timestamp":     time.Unix(callData.Timestamp, 0).Format(time.RFC3339),
            "caller_number": callData.CallerNumber,
        }
        if callData.CallerNumber != "" {
            body["Number"] = callData.CallerNumber
        }
    } else {
        body["Number"] = evt.Info.SourceString()
        body["message"] = data
        body["PushName"] = evt.Info.PushName
        body["timestamp"] = evt.Info.Timestamp.Format(time.RFC3339)
    }

    body["IsGroup"] = isGroup
    if groupName != "" {
        body["GroupName"] = groupName
    }
    body["MyNumber"] = isMyNumber
    body["Port"] = config.AppPort

    return body, nil
}

func submitWebhook(payload map[string]interface{}, url string) error {
    client := &http.Client{Timeout: 10 * time.Second}

    postBody, err := json.Marshal(payload)
    if err != nil {
        return pkgError.WebhookError(fmt.Sprintf("Falha ao serializar corpo: %v", err))
    }

    req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(postBody))
    if err != nil {
        return pkgError.WebhookError(fmt.Sprintf("Erro ao criar objeto HTTP: %v", err))
    }

    secretKey := []byte(config.WhatsappWebhookSecret)
    signature, err := getMessageDigestOrSignature(postBody, secretKey)
    if err != nil {
        return pkgError.WebhookError(fmt.Sprintf("Erro ao criar assinatura: %v", err))
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Hub-Signature-256", fmt.Sprintf("sha256=%s", signature))

    var attempt int
    var maxAttempts = 5
    var sleepDuration = 1 * time.Second

    for attempt = 0; attempt < maxAttempts; attempt++ {
        if _, err = client.Do(req); err == nil {
            logrus.Infof("Webhook enviado com sucesso na tentativa %d", attempt+1)
            return nil
        }
        logrus.Warnf("Tentativa %d de enviar webhook falhou: %v", attempt+1, err)
        time.Sleep(sleepDuration)
        sleepDuration *= 2
    }

    return pkgError.WebhookError(fmt.Sprintf("Erro ao enviar webhook após %d tentativas: %v", attempt, err))
}

type PresenceRequest struct {
    JID      string `json:"jid"`
    Presence string `json:"presence"`
    Duration int    `json:"duration"`
}

type EndCallRequest struct {
    CallID string `json:"call_id"`
}

func SendPresenceHandler(w http.ResponseWriter, r *http.Request) {
    var req PresenceRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        logrus.Errorf("Falha ao decodificar corpo da requisição: %v", err)
        http.Error(w, pkgError.WebhookError(fmt.Sprintf("Corpo da requisição inválido: %v", err)).Error(), http.StatusBadRequest)
        return
    }

    if req.JID == "" || (req.Presence != "typing" && req.Presence != "recording") {
        logrus.Errorf("JID ou tipo de presença inválido: JID=%s, Presence=%s", req.JID, req.Presence)
        http.Error(w, pkgError.WebhookError("JID e presença (typing ou recording) são obrigatórios").Error(), http.StatusBadRequest)
        return
    }

    if req.Duration <= 0 {
        req.Duration = 5
    }

    logrus.Debugf("Processando requisição de presença: JID=%s, Presence=%s, Duration=%d", req.JID, req.Presence, req.Duration)
    jid, err := ValidateJidWithLogin(cli, req.JID)
    if err != nil {
        logrus.Errorf("JID inválido %s: %v", req.JID, err)
        http.Error(w, pkgError.WebhookError(fmt.Sprintf("JID inválido: %v", err)).Error(), http.StatusBadRequest)
        return
    }

    var presence types.ChatPresence
    var media types.ChatPresenceMedia
    switch req.Presence {
    case "typing":
        presence = types.ChatPresenceComposing
        media = types.ChatPresenceMediaText
    case "recording":
        presence = types.ChatPresenceComposing
        media = types.ChatPresenceMediaAudio
    default:
        logrus.Errorf("Tipo de presença não suportado: %s", req.Presence)
        http.Error(w, pkgError.WebhookError("Tipo de presença não suportado").Error(), http.StatusBadRequest)
        return
    }

    go func() {
        logrus.Debugf("Enviando presença inicial: JID=%s, Presence=%s, Media=%s", jid.String(), presence, media)
        if err := cli.SendChatPresence(jid, presence, media); err != nil {
            logrus.Errorf("Falha ao enviar presença %s para %s: %v", req.Presence, jid.String(), err)
            return
        }
        logrus.Infof("Presença %s enviada para %s por %d segundos", req.Presence, jid.String(), req.Duration)

        logrus.Debugf("Agendando presença pausada para JID=%s após %d segundos", jid.String(), req.Duration)
        time.Sleep(time.Duration(req.Duration) * time.Second)

        logrus.Debugf("Enviando presença pausada: JID=%s", jid.String())
        if err := cli.SendChatPresence(jid, types.ChatPresencePaused, types.ChatPresenceMediaText); err != nil {
            logrus.Warnf("Falha ao enviar presença pausada após %s para %s: %v", req.Presence, jid.String(), err)
        } else {
            logrus.Infof("Presença pausada enviada para %s", jid.String())
        }
    }()

    response := map[string]string{
        "status":  "success",
        "message": fmt.Sprintf("Presença %s agendada para %s por %d segundos", req.Presence, jid.String(), req.Duration),
    }
    logrus.Debugf("Retornando resposta imediata para requisição de presença: JID=%s", jid.String())
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        logrus.Errorf("Falha ao codificar resposta: %v", err)
    }
}

func EndCallHandler(w http.ResponseWriter, r *http.Request) {
    logrus.Info("Recebida requisição para encerrar chamada")
    var req EndCallRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        logrus.Errorf("Falha ao decodificar requisição de encerrar chamada: %v", err)
        http.Error(w, pkgError.WebhookError(fmt.Sprintf("Corpo da requisição inválido: %v", err)).Error(), http.StatusBadRequest)
        return
    }

    if req.CallID == "" {
        logrus.Errorf("call_id ausente na requisição")
        http.Error(w, pkgError.WebhookError("call_id é obrigatório").Error(), http.StatusBadRequest)
        return
    }

    logrus.Debugf("Processando requisição de encerrar chamada: CallID=%s", req.CallID)

    callJIDsMutex.Lock()
    jid, exists := callJIDs[req.CallID]
    callJIDsMutex.Unlock()

    if !exists {
        logrus.Errorf("Nenhuma chamada encontrada para CallID=%s", req.CallID)
        http.Error(w, pkgError.WebhookError("Chamada não encontrada ou já encerrada").Error(), http.StatusNotFound)
        return
    }

    logrus.Debugf("Tentando encerrar chamada: CallID=%s, JID=%s", req.CallID, jid.String())
    err := cli.RejectCall(jid, req.CallID)
    if err != nil {
        logrus.Errorf("Falha ao encerrar chamada %s para %s: %v", req.CallID, jid.String(), err)
        http.Error(w, pkgError.WebhookError(fmt.Sprintf("Falha ao encerrar chamada: %v", err)).Error(), http.StatusInternalServerError)
        return
    }

    callJIDsMutex.Lock()
    delete(callJIDs, req.CallID)
    callJIDsMutex.Unlock()

    logrus.Infof("Chamada %s encerrada com sucesso para %s via endpoint", req.CallID, jid.String())

    response := map[string]string{
        "status":  "success",
        "message": fmt.Sprintf("Chamada %s encerrada", req.CallID),
    }
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        logrus.Errorf("Falha ao codificar resposta: %v", err)
    }
}
