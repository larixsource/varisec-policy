package cl.larix.varisec;

import io.apiman.gateway.engine.beans.PolicyFailure;
import io.apiman.gateway.engine.beans.PolicyFailureType;
import io.apiman.test.common.mock.EchoResponse;
import io.apiman.test.policies.*;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;
import java.util.Map;

@TestingPolicy(SecurityPolicy.class)
@Configuration("{}")
public class SecurityPolicyTest extends ApimanPolicyTest {
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private static final int HTTP_BAD_REQUEST = 400;
    private static final int HTTP_UNAUTHORIZED = 401;

    private static final int AUTH_NOT_PROVIDED = 12005;
    private static final int MISSING_CLAIM = 12009;
    private static final int BAD_ORGANIZATION_PARAMETER = 12009;
    private static final int UNKNOWN_ORGANIZATION = 12009;

    private static final String VARI_USER_ID_HEADER = "X-Vari-UserId";
    private static final String VARI_IDPUSER_ID_HEADER = "X-Vari-IDPUserId";
    private static final String VARI_ROLES_HEADER = "X-Vari-Roles";
    private static final String VARI_ORGANIZATIONS_HEADER = "X-Vari-Organizations";
    private static final String ORG_QUERY_PARAM = "org";

    @Test
    public void testAdminToken() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5blhDLVJqTVNNWVJJams1SktrV3ZCdW52SHpkU2F2YWRldFVjYUxqeVZZIn0.eyJqdGkiOiJiNTEzYjBlZC1kOGVhLTQzNTEtOWRhZS0xZjY5MGU0MGUxMjQiLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJlZTczODk2My1lYWZiLTQ1NjYtOGYwMS0zYmJkNGQyYmRkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJ2YXJpX29yZ2FuaXphdGlvbl9pZCI6WzBdLCJ2YXJpX3VzZXJfaWQiOjEsIm5hbWUiOiJKb3JnZSBSaXF1ZWxtZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpyaXF1ZWxtZSIsImdpdmVuX25hbWUiOiJKb3JnZSIsImZhbWlseV9uYW1lIjoiUmlxdWVsbWUiLCJlbWFpbCI6ImpvcmdlQGxhcml4LmNsIn0.PPFjf2xcxLEW-_DGFkeOMK1gTQypizOWSiFSQ7ZbFPps9i0fWdDcnxieJ93YaivKKY8JlzAQYbpNFG99fuTHZW3e3Fppb57z1jFhIxdgaio37VMIRE3rfjRYLlO_bDO3UlviKq2b5AmpqKUFke9x-BqSbhk944geotQYosRZf8D_yoviT4Y7cmVXChM1x2hPfSpdKjJiv98KDvE9P5K6yxxUpXLA3TJZVsupoBnJC049i_PE4HpgVzFxvRXEnuWkM0nwpdeYHwZtm51OoPJ8mQjV8Jk6Cj-BXTAl9rfYKGcMkQ7G6_2HRf1UlxHyiM3tbjHFAzUXjShlKIligv4blQ");

        PolicyTestResponse response = send(request);
        EchoResponse echo = response.entity(EchoResponse.class);
        Assert.assertNotNull(echo);

        Map<String, String> headers = echo.getHeaders();

        Assert.assertEquals("ee738963-eafb-4566-8f01-3bbd4d2bdd9b", headers.get(VARI_IDPUSER_ID_HEADER));
        Assert.assertEquals("1", headers.get(VARI_USER_ID_HEADER));
        Assert.assertEquals("*", headers.get(VARI_ORGANIZATIONS_HEADER));

        String[] roles = headers.get(VARI_ROLES_HEADER).split(",");
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("admin")));
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("uma_authorization")));

        Assert.assertFalse(headers.containsKey(AUTHORIZATION_HEADER));
    }

    @Test
    public void testUserToken() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.xeKCdynapHRgWh4U_ZaedMoWUfmMA1FqAYwonTZZf_8");

        PolicyTestResponse response = send(request);
        EchoResponse echo = response.entity(EchoResponse.class);
        Assert.assertNotNull(echo);

        Map<String, String> headers = echo.getHeaders();

        Assert.assertEquals("f7cef67c-41f9-4f8d-b917-dda2fca53de8", headers.get(VARI_IDPUSER_ID_HEADER));
        Assert.assertEquals("5", headers.get(VARI_USER_ID_HEADER));
        Assert.assertEquals("2", headers.get(VARI_ORGANIZATIONS_HEADER));

        String[] roles = headers.get(VARI_ROLES_HEADER).split(",");
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("user")));
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("uma_authorization")));

        Assert.assertFalse(headers.containsKey(AUTHORIZATION_HEADER));
    }

    @Test
    public void testAdminTokenWithOrg() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/").query(ORG_QUERY_PARAM, "42")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5blhDLVJqTVNNWVJJams1SktrV3ZCdW52SHpkU2F2YWRldFVjYUxqeVZZIn0.eyJqdGkiOiJiNTEzYjBlZC1kOGVhLTQzNTEtOWRhZS0xZjY5MGU0MGUxMjQiLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJlZTczODk2My1lYWZiLTQ1NjYtOGYwMS0zYmJkNGQyYmRkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJ2YXJpX29yZ2FuaXphdGlvbl9pZCI6WzBdLCJ2YXJpX3VzZXJfaWQiOjEsIm5hbWUiOiJKb3JnZSBSaXF1ZWxtZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpyaXF1ZWxtZSIsImdpdmVuX25hbWUiOiJKb3JnZSIsImZhbWlseV9uYW1lIjoiUmlxdWVsbWUiLCJlbWFpbCI6ImpvcmdlQGxhcml4LmNsIn0.PPFjf2xcxLEW-_DGFkeOMK1gTQypizOWSiFSQ7ZbFPps9i0fWdDcnxieJ93YaivKKY8JlzAQYbpNFG99fuTHZW3e3Fppb57z1jFhIxdgaio37VMIRE3rfjRYLlO_bDO3UlviKq2b5AmpqKUFke9x-BqSbhk944geotQYosRZf8D_yoviT4Y7cmVXChM1x2hPfSpdKjJiv98KDvE9P5K6yxxUpXLA3TJZVsupoBnJC049i_PE4HpgVzFxvRXEnuWkM0nwpdeYHwZtm51OoPJ8mQjV8Jk6Cj-BXTAl9rfYKGcMkQ7G6_2HRf1UlxHyiM3tbjHFAzUXjShlKIligv4blQ");

        PolicyTestResponse response = send(request);
        EchoResponse echo = response.entity(EchoResponse.class);
        Assert.assertNotNull(echo);

        Map<String, String> headers = echo.getHeaders();

        Assert.assertEquals("ee738963-eafb-4566-8f01-3bbd4d2bdd9b", headers.get(VARI_IDPUSER_ID_HEADER));
        Assert.assertEquals("1", headers.get(VARI_USER_ID_HEADER));
        Assert.assertEquals("*", headers.get(VARI_ORGANIZATIONS_HEADER));

        String[] roles = headers.get(VARI_ROLES_HEADER).split(",");
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("admin")));
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("uma_authorization")));

        Assert.assertFalse(headers.containsKey(AUTHORIZATION_HEADER));
    }

    @Test
    public void testUserTokenWithOrg() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/").query(ORG_QUERY_PARAM, "2")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.xeKCdynapHRgWh4U_ZaedMoWUfmMA1FqAYwonTZZf_8");

        PolicyTestResponse response = send(request);
        EchoResponse echo = response.entity(EchoResponse.class);
        Assert.assertNotNull(echo);

        Map<String, String> headers = echo.getHeaders();

        Assert.assertEquals("f7cef67c-41f9-4f8d-b917-dda2fca53de8", headers.get(VARI_IDPUSER_ID_HEADER));
        Assert.assertEquals("5", headers.get(VARI_USER_ID_HEADER));
        Assert.assertEquals("2", headers.get(VARI_ORGANIZATIONS_HEADER));

        String[] roles = headers.get(VARI_ROLES_HEADER).split(",");
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("user")));
        Assert.assertTrue(Arrays.stream(roles).anyMatch(role -> role.equals("uma_authorization")));

        Assert.assertFalse(headers.containsKey(AUTHORIZATION_HEADER));
    }

    @Test
    public void testUserTokenWithOrgUnauthorized() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/").query(ORG_QUERY_PARAM, "1")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.xeKCdynapHRgWh4U_ZaedMoWUfmMA1FqAYwonTZZf_8");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(UNKNOWN_ORGANIZATION, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authorization, failure.getType());
            Assert.assertEquals("Unknown organization", failure.getMessage());
        }
    }

    @Test
    public void testUserTokenWithOrgBadFormat() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/").query(ORG_QUERY_PARAM, "a")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.xeKCdynapHRgWh4U_ZaedMoWUfmMA1FqAYwonTZZf_8");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_BAD_REQUEST, failure.getResponseCode());
            Assert.assertEquals(BAD_ORGANIZATION_PARAMETER, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Other, failure.getType());
            Assert.assertEquals("Invalid org parameter value", failure.getMessage());
        }
    }

    @Test
    @Ignore
    public void testUserTokenWithOrgMultivalued() throws Throwable {
        // TODO: PolicyTestRequest doesn't seems to support multi valued query parameters.
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/").query(ORG_QUERY_PARAM, "1").query("org", "2")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.xeKCdynapHRgWh4U_ZaedMoWUfmMA1FqAYwonTZZf_8");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_BAD_REQUEST, failure.getResponseCode());
            Assert.assertEquals(BAD_ORGANIZATION_PARAMETER, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Other, failure.getType());
            Assert.assertEquals("At most one org query parameter can be used", failure.getMessage());
        }
    }

    @Test
    public void testMissingSub() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.qM3BOONnSPf0ayobqpn2hNlWiyYk783Yr-rSad9W9J0");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(MISSING_CLAIM, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authentication, failure.getType());
            Assert.assertEquals("Missing sub from token", failure.getMessage());
        }
    }

    @Test
    public void testMissingUserId() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sIm5hbWUiOiJDbGF1ZGlhIFJpcXVlbG1lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiY2xhdWRpemEiLCJnaXZlbl9uYW1lIjoiQ2xhdWRpYSIsImZhbWlseV9uYW1lIjoiUmlxdWVsbWUiLCJlbWFpbCI6ImNsYXVkaXphXzAwQGhvdG1haWwuY29tIn0.7FLJrcwv_nHfiDVoEkbsTSUyXAsOczyclUq_oUF4Vk0");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(MISSING_CLAIM, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authentication, failure.getType());
            Assert.assertEquals("Missing vari_user_id from token", failure.getMessage());
        }
    }

    @Test
    public void testMissingOrganizations() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.soBQF7Qf2k_9Ux2KjsS0fHGHtDrrp-Zai47R65RAQ5Y");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(MISSING_CLAIM, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authentication, failure.getType());
            Assert.assertEquals("Missing vari_organization_id from token", failure.getMessage());
        }
    }

    @Test
    public void testMissingRealmAccess() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.FmZJG-3KEWxAtwhgNQjwzJ-6Vnr7AZ4iMj_mdHqV0L0");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(MISSING_CLAIM, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authentication, failure.getType());
            Assert.assertEquals("Missing realm_access.roles from token", failure.getMessage());
        }
    }

    @Test
    public void testMissingRoles() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/")
                .header(AUTHORIZATION_HEADER, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwZDI1MTQ4My1iODUyLTQzZmItOWYyZC1mMGFhNDY3NjI1YTciLCJleHAiOjE1MDU0MTA1MDUsIm5iZiI6MCwiaWF0IjoxNTA1NDEwMjA1LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYXV0aC9yZWFsbXMvcnV0YWNvbnRyb2wiLCJhdWQiOiJhcGltYW4iLCJzdWIiOiJmN2NlZjY3Yy00MWY5LTRmOGQtYjkxNy1kZGEyZmNhNTNkZTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGltYW4iLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJjZGZhYjdkMS00OWZmLTQ3ZDItOGM2NC1kZTAyNjU5ZTdmNGQiLCJhY3IiOiIxIiwiY2xpZW50X3Nlc3Npb24iOiIxMDcxMTU5MS04OTAxLTRkMDctYTc1YS0xMTc2ZDZhMGRiMWEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnt9LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfX0sInZhcmlfb3JnYW5pemF0aW9uX2lkIjpbMl0sInZhcmlfdXNlcl9pZCI6NSwibmFtZSI6IkNsYXVkaWEgUmlxdWVsbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjbGF1ZGl6YSIsImdpdmVuX25hbWUiOiJDbGF1ZGlhIiwiZmFtaWx5X25hbWUiOiJSaXF1ZWxtZSIsImVtYWlsIjoiY2xhdWRpemFfMDBAaG90bWFpbC5jb20ifQ.-LzEpsAQ9YHfDItDxRGscgjl4mdlSC2cpfACuHQBFwk");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(MISSING_CLAIM, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authentication, failure.getType());
            Assert.assertEquals("Missing realm_access.roles from token", failure.getMessage());
        }
    }

    @Test
    public void testNoToken() throws Throwable {
        PolicyTestRequest request = PolicyTestRequest.build(PolicyTestRequestType.GET, "/");
        try {
            send(request);
        } catch (PolicyFailureError e) {
            PolicyFailure failure = e.getFailure();
            Assert.assertEquals(HTTP_UNAUTHORIZED, failure.getResponseCode());
            Assert.assertEquals(AUTH_NOT_PROVIDED, failure.getFailureCode());
            Assert.assertEquals(PolicyFailureType.Authentication, failure.getType());
            Assert.assertEquals("", failure.getMessage());
        }
    }
}
