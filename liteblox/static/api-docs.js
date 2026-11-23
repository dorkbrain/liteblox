// The Swagger page for /api/v1: the spec comes with the session cookie; calls need a token (Authorize)
window.addEventListener('load', function () {
  window.ui = SwaggerUIBundle({
    url: '/api/v1/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    persistAuthorization: false,
    defaultModelsExpandDepth: 0,
  });
});
