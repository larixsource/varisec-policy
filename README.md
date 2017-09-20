# Vari Security Policy

This is an [APIMAN](http://www.apiman.io) plugin to apply and enforce the security policy defined by the REST API of
**Vari**, our fleet management system (available at [rutacontrol.com](https://www.rutacontrol.com)).

The plugin takes a **previously validated** JWT token from the Authorization header, with a body containing at least
the fields:

```json
{
  "sub": "ee738963-eafb-4566-8f01-3bbd4d2bdd9b",
  "realm_access": {
    "roles": [
      "operator",
      "fleet_manager"
    ]
  },
  "vari_organization_id": [2, 4],
  "vari_user_id": 1
}
```

and generates the headers:

* X-Vari-UserId: 1
* X-Vari-IDPUserId: ee738963-eafb-4566-8f01-3bbd4d2bdd9b
* X-Vari-Roles: operator,fleet_manager
* X-Vari-Organizations: 2,4

Additionally, the plugin checks the query parameter **org** if present, that contains the id of an organization.
Any client request specifying an organization must match the vari_organization_id claim contents, so in our example:

* GET /assets?org=1 or GET /assets?org=3 should return an authorization error.
* GET /assets?org=2 or GET /assets?org=4 should be OK.

## Notes

* This plugin obviously won't be useful as-is to others, we've publish it hoping it could be useful as an example to
anyone looking to implement a custom policy plugin.
* Initially, we wanted to use multi-valued headers (i.e: one X-Vari-Role per each role), but the APIMAN Java API doesn't
seem to fully support this (any advice regarding this would be appreciated).
