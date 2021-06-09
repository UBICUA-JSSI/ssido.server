/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssido.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ssido.util.JacksonCodecs;
import ssido.core.data.ByteArray;
import ssido.core.data.exception.Base64UrlException;
import ssido.core.extension.appid.InvalidAppIdException;
import ssido.core.meta.VersionInfo;
import ssido.data.AssertionRequestWrapper;
import ssido.data.RegistrationRequest;
import ssido.web.util.Either;
import java.io.IOException;


import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.enterprise.context.RequestScoped;
import javax.ws.rs.Consumes;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.Produces;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * REST Web Service
 *
 * @author ITON Solutions
 */
@Path("/v1")
@RequestScoped
@Produces(MediaType.APPLICATION_JSON)
public class WebAuthnRest {
    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnRest.class);

    private final SsidoService server;
    private final ObjectMapper jsonMapper = JacksonCodecs.json();
    private final JsonNodeFactory jsonFactory = JsonNodeFactory.instance;

    public WebAuthnRest() throws InvalidAppIdException, CertificateException {
        this(new SsidoService());
    }

    public WebAuthnRest(SsidoService server) {
        this.server = server;
    }

    @Context
    private UriInfo uriInfo;

    private final class IndexResponse {
        public final Index actions = new Index();
        public final Info info = new Info();
        private IndexResponse() throws MalformedURLException {
        }
    }
    private final class Index {
        public final URL addCredential;
        public final URL authenticate;
        public final URL deleteAccount;
        public final URL deregister;
        public final URL register;


        public Index() throws MalformedURLException {
            addCredential = uriInfo.getAbsolutePathBuilder().path("action").path("add-credential").build().toURL();
            authenticate = uriInfo.getAbsolutePathBuilder().path("authenticate").build().toURL();
            deleteAccount = uriInfo.getAbsolutePathBuilder().path("delete-account").build().toURL();
            deregister = uriInfo.getAbsolutePathBuilder().path("action").path("deregister").build().toURL();
            register = uriInfo.getAbsolutePathBuilder().path("register").build().toURL();
        }
    }
    private final class Info {
        public final URL version;

        public Info() throws MalformedURLException {
            version = uriInfo.getAbsolutePathBuilder().path("version").build().toURL();
        }
    }

    @GET
    public Response index() throws IOException {
        LOG.debug("Get urls info: {}", writeJson(new IndexResponse()));
        return Response.ok(writeJson(new IndexResponse())).build();
    }

    private static final class VersionResponse {
        public final VersionInfo version = VersionInfo.getInstance();
    }
    
    @GET
    @Path("version")
    public Response version() throws JsonProcessingException {
        return Response.ok(writeJson(new VersionResponse())).build();
    }

    private final class StartRegistrationResponse {
        public final boolean success = true;
        public final RegistrationRequest request;
        public final StartRegistrationActions actions = new StartRegistrationActions();
        private StartRegistrationResponse(RegistrationRequest request) throws MalformedURLException {
            this.request = request;
        }
    }
    
    private final class StartRegistrationActions {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        public final URL finishU2f = uriInfo.getAbsolutePathBuilder().path("finish-u2f").build().toURL();
        private StartRegistrationActions() throws MalformedURLException {
        }
    }

    @Path("register")
    @POST
    public Response startRegistration( 
            @Nonnull @FormParam("username") String username,
            @Nonnull @FormParam("displayName") String displayName,
            @FormParam("credentialNickname") String credentialNickname,
            @FormParam("requireResidentKey") @DefaultValue("false") boolean requireResidentKey
    ) throws MalformedURLException {
        
        LOG.debug("Start registration username: {}, displayName: {}, credentialNickname: {}, requireResidentKey: {}", username, displayName, credentialNickname, requireResidentKey);
        
        Either<String, RegistrationRequest> result = server.startRegistration(
            username,
            displayName,
            Optional.ofNullable(credentialNickname),
            null,
            requireResidentKey
        );

        if (result.isRight()) {
            return startResponse("Start registration", new StartRegistrationResponse(result.right().get()));
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    @Path("register/finish")
    @POST
    public Response finishRegistration(@Nonnull String responseJson) {
        LOG.trace("finishRegistration responseJson: {}", responseJson);
        Either<List<String>, SsidoService.SuccessfulRegistrationResult> result = server.finishRegistration(responseJson);
        return finishResponse(
            result,
            "Attestation verification failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishRegistration",
            responseJson
        );
    }

    @Path("register/finish-u2f")
    @POST
    public Response finishU2fRegistration(@Nonnull String responseJson) {
        LOG.trace("finishRegistration responseJson: {}", responseJson);
        Either<List<String>, SsidoService.SuccessfulU2fRegistrationResult> result = server.finishU2fRegistration(responseJson);
        return finishResponse(
            result,
            "U2F registration failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishU2fRegistration",
            responseJson
        );
    }

    private final class StartAuthenticationResponse {
        public final boolean success = true;
        public final AssertionRequestWrapper request;
        public final StartAuthenticationActions actions = new StartAuthenticationActions();
        private StartAuthenticationResponse(AssertionRequestWrapper request) throws MalformedURLException {
            this.request = request;
        }
    }
    private final class StartAuthenticationActions {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        private StartAuthenticationActions() throws MalformedURLException {
        }
    }
    @Path("authenticate")
    @POST
    public Response startAuthentication( @FormParam("username") String username) throws MalformedURLException {
        LOG.trace("startAuthentication username: {}", username);
        Either<List<String>, AssertionRequestWrapper> request = server.startAuthentication(Optional.ofNullable(username), Optional.empty());
        if (request.isRight()) {
            return startResponse("startAuthentication", new StartAuthenticationResponse(request.right().get()));
        } else {
            return messagesJson(Response.status(Status.BAD_REQUEST), request.left().get());
        }
    }

    @Path("authenticate/finish")
    @POST
    public Response finishAuthentication(@Nonnull String responseJson) {
        LOG.trace("finishAuthentication responseJson: {}", responseJson);

        Either<List<String>, SsidoService.SuccessfulAuthenticationResult> result = server.finishAuthentication(responseJson);

        return finishResponse(
            result,
            "Authentication verification failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishAuthentication",
            responseJson
        );
    }

    @Path("action/{action}/finish")
    @POST
    public Response finishAuthenticatedAction(
        @Nonnull @PathParam("action") String action,
        @Nonnull String responseJson
    ) {
        LOG.trace("finishAuthenticatedAction: {}, responseJson: {}", action, responseJson);
        Either<List<String>, ?> mappedResult = server.finishAuthenticatedAction(responseJson);

        return finishResponse(
            mappedResult,
            "Action succeeded; further error message(s) were unfortunately lost to an internal server error.",
            "finishAuthenticatedAction",
            responseJson
        );
    }

    private final class StartAuthenticatedActionResponse {
        public final boolean success = true;
        public final AssertionRequestWrapper request;
        public final StartAuthenticatedActionActions actions = new StartAuthenticatedActionActions();
        private StartAuthenticatedActionResponse(AssertionRequestWrapper request) throws MalformedURLException {
            this.request = request;
        }
    }
    private final class StartAuthenticatedActionActions {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        public final URL finishU2f = uriInfo.getAbsolutePathBuilder().path("finish-u2f").build().toURL();
        private StartAuthenticatedActionActions() throws MalformedURLException {
        }
    }

    @Path("action/add-credential")
    @POST
    public Response addCredential(
        @Nonnull @FormParam("username") String username,
        @FormParam("credentialNickname") String credentialNickname,
        @FormParam("requireResidentKey") @DefaultValue("false") boolean requireResidentKey
    ) throws MalformedURLException {
        LOG.trace("addCredential username: {}, credentialNickname: {}, requireResidentKey: {}", username, credentialNickname, requireResidentKey);

        Either<List<String>, AssertionRequestWrapper> result = server.startAddCredential(username, Optional.ofNullable(credentialNickname), requireResidentKey, (RegistrationRequest request) -> {
            try {
                return Either.right(new StartRegistrationResponse(request));
            } catch (MalformedURLException e) {
                LOG.error("Failed to construct registration response", e);
                return Either.left(Arrays.asList("Failed to construct response. This is probably a bug in the server."));
            }
        });

        if (result.isRight()) {
            return startResponse("addCredential", new StartAuthenticatedActionResponse(result.right().get()));
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    @Path("action/add-credential/finish/finish")
    @POST
    public Response finishAddCredential(@Nonnull String responseJson) {
        return finishRegistration(responseJson);
    }

    @Path("action/add-credential/finish/finish-u2f")
    @POST
    public Response finishU2fAddCredential(@Nonnull String responseJson) {
        return finishU2fRegistration(responseJson);
    }

    @Path("action/deregister")
    @POST
    public Response deregisterCredential(
        @Nonnull @FormParam("username") String username,
        @Nonnull @FormParam("credentialId") String credentialIdBase64
    ) throws MalformedURLException {
        LOG.trace("deregisterCredential username: {}, credentialId: {}", username, credentialIdBase64);

        final ByteArray credentialId;
        try {
            credentialId = ByteArray.fromBase64Url(credentialIdBase64);
        } catch (Base64UrlException e) {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                "Credential ID is not valid Base64Url data: " + credentialIdBase64
            );
        }

        Either<List<String>, AssertionRequestWrapper> result = server.deregisterCredential(username, credentialId, (credentialRegistration -> {
            try {
                return ((ObjectNode) jsonFactory.objectNode()
                        .set("success", jsonFactory.booleanNode(true)))
                        .set("droppedRegistration", jsonMapper.readTree(writeJson(credentialRegistration)))
                ;
            } catch (IOException e) {
                LOG.error("Failed to write response as JSON", e);
                throw new RuntimeException(e);
            }
        }));

        if (result.isRight()) {
            return startResponse("deregisterCredential", new StartAuthenticatedActionResponse(result.right().get()));
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    @Path("delete-account")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @POST
    public Response deleteAccount(@Nonnull @FormParam("username") String username) {
        LOG.debug("deleteAccount username: {}", username);

        Either<List<String>, JsonNode> result = server.deleteAccount(username, () ->
            ((ObjectNode) jsonFactory.objectNode()
                .set("success", jsonFactory.booleanNode(true)))
                .set("deletedAccount", jsonFactory.textNode(username))
        );

        if (result.isRight()) {
            return Response.ok(result.right().get().toString()).build();
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    private Response startResponse(String operationName, Object request) {
        try {
            String json = writeJson(request);
            LOG.debug("{} JSON response: {}", operationName, json);
            return Response.ok(json).build();
        } catch (IOException e) {
            LOG.error("Failed to encode response as JSON: {}", request, e);
            return jsonFail();
        }
    }

    private Response finishResponse(Either<List<String>, ?> result, String jsonFailMessage, String methodName, String responseJson) {
        if (result.isRight()) {
            try {
                return Response.ok(
                    writeJson(result.right().get())
                ).build();
            } catch (JsonProcessingException e) {
                LOG.error("Failed to encode response as JSON: {}", result.right().get(), e);
                return messagesJson(
                    Response.ok(),
                    jsonFailMessage
                );
            }
        } else {
            LOG.debug("fail {} responseJson: {}", methodName, responseJson);
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    private Response jsonFail() {
        return Response.status(Status.INTERNAL_SERVER_ERROR)
            .entity("{\"messages\":[\"Failed to encode response as JSON\"]}")
            .build();
    }

    private Response messagesJson(ResponseBuilder response, String message) {
        return messagesJson(response, Arrays.asList(message));
    }

    private Response messagesJson(ResponseBuilder response, List<String> messages) {
        LOG.debug("Encoding messages as JSON: {}", messages);
        try {
            return response.entity(
                writeJson(
                    jsonFactory.objectNode()
                        .set("messages", jsonFactory.arrayNode()
                            .addAll(messages.stream().map(jsonFactory::textNode).collect(Collectors.toList()))
                        )
                )
            ).build();
        } catch (JsonProcessingException e) {
            LOG.error("Failed to encode messages as JSON: {}", messages, e);
            return jsonFail();
        }
    }

    private String writeJson(Object o) throws JsonProcessingException {
        if (uriInfo.getQueryParameters().keySet().contains("pretty")) {
            return jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(o);
        } else {
            return jsonMapper.writeValueAsString(o);
        }
    }

}
