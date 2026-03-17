# sql-ntlm-relay

A TDS protocol relay that accepts SQL Server connections with SQL authentication and re-authenticates to the upstream server using NTLM/Windows authentication. Useful when your client doesn't support NTLM (e.g., macOS) but the server requires it.

The relay performs a full TLS MITM — both the client and server see an encrypted connection, so all TDS features (MARS, Object Explorer, connection pooling, etc.) work correctly.

## Build

```sh
go build -o sql-ntlm-relay .
```

## Usage

```sh
sql-ntlm-relay -port 11433 -remote sqlserver.corp.example.com:1433 [-v]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `1433` | Port to listen on (binds to localhost only) |
| `-listen` | `false` | Listen on all interfaces instead of localhost |
| `-remote` | (required) | Remote SQL Server `host:port` |
| `-allow-remote-env` | `false` | Allow `use_env` credentials when `-listen` is set |
| `-v` | `false` | Verbose TDS packet logging |

By default the relay binds to `127.0.0.1` and `[::1]` (localhost only) on both IPv4 and IPv6. Use `-listen` to bind to all interfaces — a warning is logged when this mode is active.

## Environment Variable Credentials

To avoid entering credentials in the client (useful for shared configs or CI), set the username and/or password to the literal string `use_env`. The relay will read the actual values from environment variables:

```sh
export NTLM_USERNAME='DOMAIN\username'
export NTLM_PASSWORD='yourpassword'
sql-ntlm-relay -port 11433 -remote sqlserver.corp.example.com:1433
```

Then in your client, use `use_env` as the username and/or password. Either field can be overridden independently — you can use a real username in the client and only set the password via env, or vice versa.

**Security note:** `use_env` is only allowed when bound to localhost (the default). If you use `-listen` to expose the relay on all interfaces, `use_env` is blocked — anyone on the network could connect and have the relay authenticate with your credentials. Pass `-allow-remote-env` to override this restriction if you understand the risk.

## Client Configuration

The relay presents a self-signed TLS certificate, so clients must be configured to trust it.

### Azure Data Studio

- Server: `localhost,11433`
- Authentication: **SQL Login**
- Username: `DOMAIN\username` (or just `username` if the domain is implied)
- Password: your Windows password
- **Encrypt**: `Mandatory` (or leave default)
- **Trust server certificate**: `Yes`

### SSMS (SQL Server Management Studio)

- Server name: `localhost,11433`
- Authentication: **SQL Server Authentication**
- Login: `DOMAIN\username`
- Password: your Windows password
- Connection Properties > **Trust server certificate**: checked
- (Or: **Encrypt connection** unchecked if your version allows it)

### .NET / C# (Microsoft.Data.SqlClient)

```csharp
var connectionString = "Server=localhost,11433;User Id=DOMAIN\\username;Password=yourpassword;TrustServerCertificate=True;";
```

Or with `SqlConnectionStringBuilder`:

```csharp
var builder = new SqlConnectionStringBuilder
{
    DataSource = "localhost,11433",
    UserID = @"DOMAIN\username",
    Password = "yourpassword",
    TrustServerCertificate = true,
    // Optionally set initial database:
    // InitialCatalog = "MyDatabase",
};
```

### .NET (System.Data.SqlClient / legacy)

```csharp
var connectionString = "Server=localhost,11433;User Id=DOMAIN\\username;Password=yourpassword;TrustServerCertificate=True;";
```

### Go (go-mssqldb)

```go
dsn := "sqlserver://DOMAIN%5Cusername:yourpassword@localhost:11433?TrustServerCertificate=true"
// or
dsn := "sqlserver://DOMAIN%5Cusername:yourpassword@localhost:11433?database=MyDatabase&TrustServerCertificate=true"
```

Note: `%5C` is the URL encoding of `\`.

### Python (pymssql)

```python
import pymssql
conn = pymssql.connect(
    server="localhost",
    port=11433,
    user=r"DOMAIN\username",
    password="yourpassword",
)
```

### Python (pyodbc)

```python
import pyodbc
conn = pyodbc.connect(
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost,11433;"
    "UID=DOMAIN\\username;"
    "PWD=yourpassword;"
    "TrustServerCertificate=Yes;"
)
```

### Node.js (tedious / mssql)

```javascript
const config = {
  server: "localhost",
  port: 11433,
  authentication: {
    type: "default",
    options: {
      userName: "DOMAIN\\username",
      password: "yourpassword",
    },
  },
  options: {
    trustServerCertificate: true,
    // database: "MyDatabase",
  },
};
```

### Java (JDBC)

```java
String url = "jdbc:sqlserver://localhost:11433;"
    + "user=DOMAIN\\username;"
    + "password=yourpassword;"
    + "trustServerCertificate=true;";
```

### DataGrip / IntelliJ

- Host: `localhost`
- Port: `11433`
- Authentication: **User & Password**
- User: `DOMAIN\username`
- Password: your Windows password
- Advanced > **trustServerCertificate**: `true`

### DBeaver

- Host: `localhost`
- Port: `11433`
- Authentication: **SQL Server Authentication**
- Username: `DOMAIN\username`
- Password: your Windows password
- Driver properties > **trustServerCertificate**: `true`

## How It Works

1. Client connects to the relay with SQL authentication credentials
2. Relay connects to the upstream SQL Server
3. PRELOGIN exchange — relay does TDS-wrapped TLS handshake with both sides (MITM)
4. Client sends LOGIN7 with SQL auth credentials over TLS
5. Relay extracts the username/password, builds an NTLM LOGIN7, and authenticates with the server
6. Server's auth response (LOGINACK, ENVCHANGE, etc.) is forwarded to the client
7. Bidirectional relay — all subsequent traffic passes through transparently

## Requirements

- Go 1.21+
- The NTLM user must have access to the target SQL Server
- Client credentials (username/password) must match a valid Windows account on the server's domain

## License

MIT
