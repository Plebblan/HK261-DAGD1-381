import pytest

from src.spec.loader import SpecLoadError, load_spec


def _write_spec(tmp_path, contents):
    path = tmp_path / "openapi.yaml"
    path.write_text(contents, encoding="utf-8")
    return path


def test_load_spec_resolves_refs_and_keeps_recursive_schema_finite(tmp_path):
    path = _write_spec(
        tmp_path,
        """\
openapi: 3.0.3
info:
  title: Example API
  version: "1.0"
servers:
  - url: https://api.example.test
paths:
  /nodes/{node_id}:
    parameters:
      - $ref: "#/components/parameters/NodeId"
    get:
      operationId: getNode
      responses:
        "200":
          $ref: "#/components/responses/NodeResponse"
components:
  parameters:
    NodeId:
      name: node_id
      in: path
      schema:
        type: string
  responses:
    NodeResponse:
      description: A node
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/Node"
  schemas:
    Node:
      type: object
      properties:
        child:
          $ref: "#/components/schemas/Node"
""",
    )

    spec = load_spec(path)

    assert spec.openapi == "3.0.3"
    assert len(spec.operations) == 1
    operation = spec.operations[0]
    assert operation.operation_id == "getNode"
    assert operation.method == "GET"
    assert operation.route_template == "/nodes/{node_id}"
    assert operation.parameters[0]["required"] is True
    assert operation.servers[0]["url"] == "https://api.example.test"
    assert operation.response_schemas["200"]["application/json"]["properties"]["child"] == {
        "$ref": "#/components/schemas/Node"
    }


def test_load_spec_rejects_external_refs_without_fetching_them(tmp_path):
    path = _write_spec(
        tmp_path,
        """\
openapi: 3.0.3
info: {title: Example API, version: "1.0"}
paths:
  /items:
    get:
      responses:
        "200":
          $ref: https://example.test/openapi.yaml#/components/responses/Item
""",
    )

    with pytest.raises(SpecLoadError, match="only local"):
        load_spec(path)


def test_load_spec_rejects_cyclic_yaml_aliases_with_domain_error(tmp_path):
    path = _write_spec(
        tmp_path,
        """\
openapi: 3.0.3
info: {title: Example API, version: "1.0"}
paths: {}
components:
  schemas:
    Node: &node
      type: object
      properties:
        child: *node
""",
    )

    with pytest.raises(SpecLoadError, match="cyclic YAML aliases"):
        load_spec(path)


def test_load_spec_rejects_non_array_parameters_with_domain_error(tmp_path):
    path = _write_spec(
        tmp_path,
        """\
openapi: 3.0.3
info: {title: Example API, version: "1.0"}
paths:
  /items:
    parameters: invalid
    get:
      responses: {}
""",
    )

    with pytest.raises(SpecLoadError, match="parameters must be arrays"):
        load_spec(path)


def test_load_spec_rejects_duplicate_yaml_keys(tmp_path):
    path = _write_spec(
        tmp_path,
        """\
openapi: 3.0.3
info: {title: Example API, version: "1.0"}
paths:
  /items:
    get:
      responses: {}
  /items:
    post:
      responses: {}
""",
    )

    with pytest.raises(SpecLoadError, match="duplicate key"):
        load_spec(path)
