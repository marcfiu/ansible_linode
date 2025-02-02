# database_postgresql

Manage a Linode PostgreSQL database.

- [Examples](#examples)
- [Parameters](#parameters)
- [Return Values](#return-values)

## Examples

```yaml
- name: Create a basic PostgreSQL database
  linode.cloud.database_postgresql:
    label: my-db
    region: us-east
    engine: postgresql/13.2
    type: g6-standard-1
    allow_list:
      - 0.0.0.0/0
    state: present
```

```yaml
- name: Create a complex 3 node PostgreSQL database
  linode.cloud.database_postgresql:
    label: my-db
    region: us-east
    engine: postgresql/13.2
    type: g6-standard-1
    allow_list:
      - 0.0.0.0/0
    encrypted: true
    cluster_size: 3
    replication_type: semi_synch
    replication_commit_type: remote_apply
    ssl_connection: true
    state: present
```

```yaml
- name: Delete a PostgreSQL database
  linode.cloud.database_postgresql:
    label: my-db
    state: absent
```


## Parameters

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `label` | <center>`str`</center> | <center>**Required**</center> | This database's unique label.   |
| `state` | <center>`str`</center> | <center>**Required**</center> | The state of this database.  **(Choices: `present`, `absent`)** |
| `allow_list` | <center>`list`</center> | <center>Optional</center> | A list of IP addresses that can access the Managed Database. Each item must be a range in CIDR format.  **(Updatable)** |
| `cluster_size` | <center>`int`</center> | <center>Optional</center> | The number of Linode Instance nodes deployed to the Managed Database.  **(Choices: `1`, `3`; Default: `1`)** |
| `encrypted` | <center>`bool`</center> | <center>Optional</center> | Whether the Managed Databases is encrypted.   |
| `engine` | <center>`str`</center> | <center>Optional</center> | The Managed Database engine in engine/version format.   |
| `region` | <center>`str`</center> | <center>Optional</center> | The Region ID for the Managed Database.   |
| `replication_type` | <center>`str`</center> | <center>Optional</center> | The replication method used for the Managed Database. Defaults to none for a single cluster and semi_synch for a high availability cluster. Must be none for a single node cluster. Must be asynch or semi_synch for a high availability cluster.  **(Choices: `none`, `asynch`, `semi_synch`; Default: `none`)** |
| `replication_commit_type` | <center>`str`</center> | <center>Optional</center> | The synchronization level of the replicating server. Must be local or off for the asynch replication type. Must be on, remote_write, or remote_apply for the semi_synch replication type.  **(Choices: `off`, `on`, `local`, `remote_write`, `remote_apply`; Default: `local`)** |
| `ssl_connection` | <center>`bool`</center> | <center>Optional</center> | Whether to require SSL credentials to establish a connection to the Managed Database.  **(Default: `True`)** |
| `type` | <center>`str`</center> | <center>Optional</center> | The Linode Instance type used by the Managed Database for its nodes.   |
| [`updates` (sub-options)](#updates) | <center>`dict`</center> | <center>Optional</center> | Configuration settings for automated patch update maintenance for the Managed Database.  **(Updatable)** |
| `wait` | <center>`bool`</center> | <center>Optional</center> | Wait for the database to have status `available` before returning.  **(Default: `True`)** |
| `wait_timeout` | <center>`int`</center> | <center>Optional</center> | The amount of time, in seconds, to wait for an image to have status `available`.  **(Default: `3600`)** |

### updates

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `day_of_week` | <center>`int`</center> | <center>**Required**</center> | The day to perform maintenance. 1=Monday, 2=Tuesday, etc.  **(Choices: `1`, `2`, `3`, `4`, `5`, `6`, `7`)** |
| `duration` | <center>`int`</center> | <center>**Required**</center> | The maximum maintenance window time in hours.  **(Choices: `1`, `3`)** |
| `hour_of_day` | <center>`int`</center> | <center>**Required**</center> | The hour to begin maintenance based in UTC time.   |
| `frequency` | <center>`str`</center> | <center>Optional</center> | Whether maintenance occurs on a weekly or monthly basis.  **(Choices: `weekly`, `monthly`; Default: `weekly`)** |
| `week_of_month` | <center>`int`</center> | <center>Optional</center> | The week of the month to perform monthly frequency updates. Defaults to None. Required for monthly frequency updates. Must be null for weekly frequency updates.   |

## Return Values

- `database` - The database in JSON serialized form.

    - Sample Response:
        ```json
        {
          "allow_list": [
            "203.0.113.1/32",
            "192.0.1.0/24"
          ],
          "cluster_size": 3,
          "created": "2022-01-01T00:01:01",
          "encrypted": false,
          "engine": "postgresql",
          "hosts": {
            "primary": "lin-0000-000-pgsql-primary.servers.linodedb.net",
            "secondary": "lin-0000-000-pgsql-primary-private.servers.linodedb.net"
          },
          "id": 123,
          "label": "example-db",
          "port": 3306,
          "region": "us-east",
          "replication_commit_type": "local",
          "replication_type": "semi_synch",
          "ssl_connection": true,
          "status": "active",
          "type": "g6-dedicated-2",
          "updated": "2022-01-01T00:01:01",
          "updates": {
            "day_of_week": 1,
            "duration": 3,
            "frequency": "weekly",
            "hour_of_day": 0,
            "week_of_month": null
          },
          "version": "13.2"
        }
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/databases/#managed-postgresql-database-view__response-samples) for a list of returned fields


- `backups` - The database backups in JSON serialized form.

    - Sample Response:
        ```json
        [
           {
              "created":"2022-01-01T00:01:01",
              "id":123,
              "label":"Scheduled - 02/04/22 11:11 UTC-XcCRmI",
              "type":"auto"
           }
        ]
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/databases/#managed-postgresql-database-backups-list) for a list of returned fields


- `ssl_cert` - The SSL CA certificate for an accessible Managed PostgreSQL Database.

    - Sample Response:
        ```json
        {
          "ca_certificate": "LS0tLS1CRUdJ...=="
        }
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/databases/#managed-postgresql-database-ssl-certificate-view__responses) for a list of returned fields


- `credentials` - The root username and password for an accessible Managed PostgreSQL Database.

    - Sample Response:
        ```json
        {
          "password": "s3cur3P@ssw0rd",
          "username": "linroot"
        }
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/databases/#managed-postgresql-database-credentials-view__responses) for a list of returned fields


