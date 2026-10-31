"""Register the lab extension routes ahead of the generic OpenAPI dispatcher."""
from app import main
from app import lab_extensions

# The OpenAPI dispatcher is a catch-all route. Starlette evaluates routes in
# registration order, so it must stay after every explicitly registered lab
# extension route or those routes will be shadowed and return the dispatcher's
# 404 response.
_dispatcher = next(route for route in main.app.router.routes if getattr(route, "name", None) == "dispatch")
main.app.router.routes.remove(_dispatcher)
main.app.router.routes.append(_dispatcher)
