# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Model Context Protocol (MCP) server that provides comprehensive access to Zabbix API functionality. It uses FastMCP to expose Zabbix operations as MCP tools and python-zabbix-utils for Zabbix API interaction.

## Development Commands

### Setup
```bash
# Install dependencies using uv package manager
uv sync

# Configure environment
cp config/.env.example .env
# Edit .env with your Zabbix server details
```

### Running the Server
```bash
# Recommended: Run with startup script (includes validation and logging)
uv run python scripts/start_server.py

# Direct execution (minimal output)
uv run python src/zabbix_mcp_server.py
```

### Testing
```bash
# Test server functionality
uv run python scripts/test_server.py

# Test with Docker
docker-compose exec zabbix-mcp python scripts/test_server.py
```

### Docker
```bash
# Build and run with Docker Compose
docker-compose up -d

# Build Docker image manually
docker build -t zabbix-mcp-server .
```

## Architecture

### Core Components

**src/zabbix_mcp_server.py** (1561 lines)
- Single-file MCP server implementation using FastMCP framework
- Contains 44 MCP tool functions organized by Zabbix API category
- All tools follow the same pattern: `@mcp.tool()` decorator wrapping Zabbix API calls

**Key Helper Functions:**
- `get_zabbix_client()` - Singleton pattern for Zabbix API client with lazy authentication (token or username/password)
- `validate_read_only()` - Enforces read-only mode by raising ValueError for write operations
- `format_response(data)` - Standardizes JSON response formatting across all tools
- `is_read_only()` - Checks READ_ONLY environment variable (defaults to "true")

### Tool Categories

The server exposes Zabbix API methods grouped into these categories:
- Host Management (host_get, host_create, host_update, host_delete)
- Host Group Management (hostgroup_*)
- Item Management (item_*)
- Trigger Management (trigger_*)
- Template Management (template_*)
- Problem & Event Management (problem_get, event_get, event_acknowledge)
- Data Retrieval (history_get, trend_get)
- User Management (user_*)
- Proxy Management (proxy_*)
- Maintenance Management (maintenance_*)
- Additional Features (graph_get, discoveryrule_get, itemprototype_get, configuration_export/import, usermacro_get, apiinfo_version)

### Transport Mechanism

The server supports two transport modes (configured via `ZABBIX_MCP_TRANSPORT`):

1. **stdio** (default): Standard input/output for MCP clients like Claude Desktop
2. **streamable-http**: HTTP-based transport for web integrations
   - Requires `AUTH_TYPE=no-auth` when using HTTP transport
   - Configurable via `ZABBIX_MCP_HOST`, `ZABBIX_MCP_PORT`, `ZABBIX_MCP_STATELESS_HTTP`

The `main()` function at the end of zabbix_mcp_server.py calls `mcp.run()` with appropriate transport parameters.

### Authentication Flow

1. Environment variables are loaded from .env file via python-dotenv
2. When first tool is called, `get_zabbix_client()` creates ZabbixAPI instance
3. Authentication attempts in order:
   - API token (ZABBIX_TOKEN) if present
   - Username/password (ZABBIX_USER + ZABBIX_PASSWORD) as fallback
4. SSL verification controlled by VERIFY_SSL (defaults to "true")

### Read-Only Mode

When `READ_ONLY=true` (default), all write operations (create/update/delete) call `validate_read_only()` which raises ValueError. This is enforced at the tool level before making any Zabbix API calls.

## Tool Implementation Pattern

All MCP tools follow this consistent pattern:

```python
@mcp.tool()
def resource_operation(required_param: str,
                       optional_param: Optional[type] = None) -> str:
    """Docstring with Args, Returns, and Raises sections.

    Args:
        required_param: Description
        optional_param: Description

    Returns:
        str: JSON formatted response
    """
    # For write operations: validate read-only mode first
    validate_read_only()  # Only for create/update/delete

    # Get authenticated client
    client = get_zabbix_client()

    # Build parameters dict
    params = {"required_param": required_param}
    if optional_param is not None:
        params["optional_param"] = optional_param

    # Call Zabbix API via python-zabbix-utils
    result = client.resource.operation(**params)

    # Return standardized JSON response
    return format_response(result)
```

## Configuration

### Required Environment Variables
- `ZABBIX_URL` - Zabbix server API endpoint (e.g., https://zabbix.example.com)

### Authentication (choose one)
- `ZABBIX_TOKEN` - API token (recommended)
- `ZABBIX_USER` + `ZABBIX_PASSWORD` - Username/password authentication

### Optional Configuration
- `READ_ONLY` - Enable read-only mode (default: "true"). Accepts: true/false, 1/0, yes/no
- `VERIFY_SSL` - SSL certificate verification (default: "true")
- `DEBUG` - Enable debug logging (default: unset)

### Transport Configuration
- `ZABBIX_MCP_TRANSPORT` - Transport type: stdio (default) or streamable-http
- `ZABBIX_MCP_HOST` - HTTP transport host (default: 127.0.0.1)
- `ZABBIX_MCP_PORT` - HTTP transport port (default: 8000)
- `ZABBIX_MCP_STATELESS_HTTP` - Stateless mode (default: false)
- `AUTH_TYPE` - Must be "no-auth" for streamable-http transport

## Adding New Tools

To add a new Zabbix API method:

1. Add the tool function following the pattern above in the appropriate category section
2. Use `@mcp.tool()` decorator
3. Include comprehensive docstring with Args/Returns/Raises sections
4. Call `validate_read_only()` for write operations
5. Use `get_zabbix_client()` to access the Zabbix API
6. Return `format_response(result)` for consistent JSON formatting
7. Follow existing parameter validation patterns (Optional types, None checks)
8. Test with both read-only and write modes

## Dependencies

- **fastmcp** (>=v2.12.4) - MCP server framework
- **zabbix_utils** (>=2.0.3) - Official Zabbix Python library
- **python-dotenv** (>=1.1.1) - Environment variable management

Managed via uv package manager (pyproject.toml).

## Code Style

- Follow PEP 8 style guidelines (per CONTRIBUTING.md)
- Use type hints for all function parameters and return values
- Write docstrings for all functions (Google-style format)
- Use meaningful variable names
- Keep functions focused and single-purpose
