/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package ssido.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import ssido.core.data.ByteArray;
import ssido.core.data.exception.Base64UrlException;
import ssido.data.User;
import ssido.core.extension.appid.InvalidAppIdException;
import ssido.data.RegistrationRequest;
import ssido.data.StartRegistrationRequest;
import ssido.util.JacksonCodecs;
import ssido.web.SsidoService.SuccessfulRegistrationResult;
import ssido.web.util.Either;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.websocket.EndpointConfig;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import javax.websocket.server.PathParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static ssido.web.WebAuthnConfig.REGISTER;

/**
 *
 * @author ITON Solutions
 */
@ServerEndpoint("/register/{action}")
public class RegisterEndpoint {
    private static final Logger LOG = LoggerFactory.getLogger(RegisterEndpoint.class);
    
    private static final int QR_MARGIN = 1;
    private static final int QR_WIDTH  = 200;
    private static final int QR_HEIGHT = 200;
    private static final ErrorCorrectionLevel QR_ERROR_CORRECTION_LEVEL = ErrorCorrectionLevel.L;
    @Inject SsidoService server;

    
    public RegisterEndpoint() throws InvalidAppIdException, CertificateException{
    }

    @OnMessage
    public void onMessage(@PathParam("action") String action, String message, Session session) throws Base64UrlException {
        
        switch (action) {
            case "register": {
                register(message, session);
                break;
            }
            
            case "finish": {
                finish(message, session);
                break;
            }

            default: {

            }
        }
    }
    
    private void finish(String message, Session session) {
        
        Either<List<String>, SuccessfulRegistrationResult> result = server.finishRegistration(message);
        
        if (result.isRight()) {
            LOG.debug("Finish registration: {}", message);
            SuccessfulRegistrationResult success = result.right().get();
            String sessionId = success.getResponse().getRequestId().getBase64Url();

            Session current = getSession(session, sessionId);
            if (current != null) {
                current.getAsyncRemote().sendText("success");
            }
        } else {
            result.left().get().forEach((error) -> {
                LOG.error(String.format("Error line: %s", error));
            });
        }
    }
    
    private void register(String message, Session session) {
        
        ObjectMapper mapper = JacksonCodecs.json();

        try {
            User user = mapper.readValue(message, User.class);
            
            String username = user.getUsername();
            String displayName = user.getDisplayName();
            Optional did = Optional.of(user.getDid());
            boolean requireResidentKey = false;
            
            if(getSession(session, user.getRequestId()) == null){
                return;
            }

            Either<String, RegistrationRequest> result = server.startRegistration(
                    username,
                    displayName,
                    did,
                    Optional.of(ByteArray.fromBase64Url(user.getRequestId())),
                    requireResidentKey
            );

            if (result.isRight()) {
                String json = mapper.writeValueAsString(new StartRegistrationRequest(result.right().get()));
                LOG.debug("Start registration: {}", json);
                session.getAsyncRemote().sendText(json);
            } else {
                LOG.error(String.format("Error line: %s", result.left().get()));
            }
        } catch (IOException | Base64UrlException e) {
            LOG.error("Error decoding message: %s -> %s", message, e.getMessage());
        }
    }
    
    @OnOpen
    public void onOpen(@PathParam("action") String action, Session session, EndpointConfig config){
        
        switch(action){
            case "init":
                String qrData = String.format(REGISTER + "/%s", session.getId());
                LOG.debug("Encode QR: {} (action: {})", qrData, action);
                String image = qrCode(qrData);
                session.getAsyncRemote().sendText(image);
                break;
            default:
                break;
        }
    }
    
    private String qrCode(String sessionId){
        
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "utf-8");
        hints.put(EncodeHintType.ERROR_CORRECTION, QR_ERROR_CORRECTION_LEVEL);
        hints.put(EncodeHintType.MARGIN, QR_MARGIN);
        
        try {
            BitMatrix bits = new QRCodeWriter().encode(sessionId, BarcodeFormat.QR_CODE, QR_WIDTH, QR_HEIGHT, hints);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bits, "png", baos);
            return String.format("data:image/png;base64,%s", Base64.getEncoder().encodeToString(baos.toByteArray()));
        } catch (WriterException | IOException e) {
        }
        return null;
    }
    
    private Session getSession(Session session, String sessionId){
        for(Session active : session.getOpenSessions()){
            if(active.getId().equals(sessionId)){
                return active;
            }
        }
        return null;
    }
}
