/*
 *
 *  * Copyright 2021 UBICUA.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
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
import ssido.data.AssertionRequestWrapper;
import ssido.data.StartAssertionRequest;
import ssido.util.JacksonCodecs;
import ssido.web.SsidoService.SuccessfulAuthenticationResult;
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
import ssido.resolver.Resolver;
import static ssido.web.WebAuthnConfig.AUTHENTICATE;
import uniresolver.ResolutionException;
import uniresolver.result.ResolveResult;

/**
 *
 * @author UBICUA
 */
@ServerEndpoint("/authenticate/{action}")
public class AuthenticateEndpoint {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateEndpoint.class);
    
    private static final int QR_MARGIN = 1;
    private static final int QR_WIDTH  = 200;
    private static final int QR_HEIGHT = 200;
    private static final ErrorCorrectionLevel QR_ERROR_CORRECTION_LEVEL = ErrorCorrectionLevel.L;
    
    @Inject SsidoService service;
//    @Inject Resolver resolver;

    
    public AuthenticateEndpoint() throws InvalidAppIdException, CertificateException{
    }

    @OnMessage
    public void onMessage(@PathParam("action") String action, String message, Session session) throws Base64UrlException {
        
        switch (action) {
            case "authenticate": {
                authenticate(message, session);
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
        
        Either<List<String>, SuccessfulAuthenticationResult> result = service.finishAuthentication(message);
        
        if (result.isRight()) {
            LOG.debug("Finish registration: {}", message);
            SuccessfulAuthenticationResult success = result.right().get();
            String sessionId = success.getResponse().getRequestId().getBase64Url();
            String username = success.getRequest().getUsername().get();

            Session current = getSession(session, sessionId);
            if (current != null) {
                current.getAsyncRemote().sendText(String.format("?status=%s&username=%s", "success", username));
            }
        } else {
            result.left().get().forEach((error) -> {
                LOG.error(String.format("Error line: %s", error));
            });
        }
    }
    
    private void authenticate(String message, Session session) {
        
        ObjectMapper mapper = JacksonCodecs.json();

        try {
            User user = mapper.readValue(message, User.class);
            String username = user.getUsername();
            
            if(getSession(session, user.getRequestId()) == null){
                return;
            }
            
            ResolveResult resolved = Resolver.getInstance().resolve("sov:did:" + user.getDid());

            Either<List<String>, AssertionRequestWrapper> result = service.startAuthentication(
                    Optional.of(username),
                    Optional.of(ByteArray.fromBase64Url(user.getRequestId())));
                    
            if (result.isRight()) {
                String json = mapper.writeValueAsString(new StartAssertionRequest(result.right().get()));
                LOG.debug("Start authenticate: {}", json);
                session.getAsyncRemote().sendText(json);
            } else {
                LOG.error(String.format("Error line: %s", result.left().get()));
            }
        } catch (IOException | Base64UrlException | ResolutionException e) {
            LOG.error("Error decoding message: %s -> %s", message, e.getMessage());
        }
    }
    
    @OnOpen
    public void onOpen(@PathParam("action") String action, Session session, EndpointConfig config){

        switch(action){
            case "init":
                String qrData = String.format(AUTHENTICATE + "/%s", session.getId());
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
