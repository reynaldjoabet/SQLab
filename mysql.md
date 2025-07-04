
services:
  # ---------------------- Yugabyte Platform UI (YBA) ----------------------
  yugaware:
    image: yugabytedb/yugabyte-platform:latest
    container_name: yugaware
    ports:
      - "7001:80" # YBA UI accessible at http://localhost:7001
    volumes:
      - yugaware-data:/opt/yugabyte/data
    environment:
      - YW_DATA_DIR=/opt/yugabyte/data
    networks:
      - yugabyte-network
    restart: unless-stopped

  # ---------------------- Masters ----------------------
  # YB-Master keeps track of various metadata (list of tables, users, roles, permissions, and so on).

  yb-master-0:
    image: yugabytedb/yugabyte:latest
    container_name: yb-master-0
    command: [
      "/home/yugabyte/bin/yb-master",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-master-0:7100",
      "--master_addresses=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--replication_factor=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    ports:
      - "7000:7000"
    networks:
      - yugabyte-network

  yb-master-1:
    image: yugabytedb/yugabyte:latest
    container_name: yb-master-1
    command: [
      "/home/yugabyte/bin/yb-master",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-master-1:7100",
      "--master_addresses=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--replication_factor=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    networks:
      - yugabyte-network

  yb-master-2:
    image: yugabytedb/yugabyte:latest
    container_name: yb-master-2
    command: [
      "/home/yugabyte/bin/yb-master",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-master-2:7100",
      "--master_addresses=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--replication_factor=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    networks:
      - yugabyte-network

  # ---------------------- TServers ----------------------
  # YB-TServer is responsible for the actual end user requests for data updates and queries.

  yb-tserver-0:
    image: yugabytedb/yugabyte:latest
    container_name: yb-tserver-0
    command: [
      "/home/yugabyte/bin/yb-tserver",
      "--tserver_master_addrs=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-tserver-0:9100",
      "--enable_ysql=true",
      "--ysql_sequence_cache_minval=1",
      "--ysql_sequence_cache_maxval=1000",
      "--ysql_num_shards_per_tserver=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    ports:
      - "5433:5433"
      - "9042:9042"
      - "9000:9000"
    healthcheck:
      test: ["CMD", "/home/yugabyte/postgres/bin/pg_isready", "-h", "yb-tserver-0"]
      interval: 10s
      timeout: 5s
      retries: 10
    depends_on:
      - yb-master-0
      - yb-master-1
      - yb-master-2
    networks:
      - yugabyte-network

  yb-tserver-1:
    image: yugabytedb/yugabyte:latest
    container_name: yb-tserver-1
    command: [
      "/home/yugabyte/bin/yb-tserver",
      "--tserver_master_addrs=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-tserver-1:9100",
      "--enable_ysql=true",
      "--ysql_sequence_cache_minval=1",
      "--ysql_sequence_cache_maxval=1000",
      "--ysql_num_shards_per_tserver=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    ports:
      - "5434:5433"
      - "9043:9042"
      - "9001:9000"
    healthcheck:
      test: ["CMD", "/home/yugabyte/postgres/bin/pg_isready", "-h", "yb-tserver-1"]
      interval: 10s
      timeout: 5s
      retries: 10
    depends_on:
      - yb-master-0
      - yb-master-1
      - yb-master-2
    networks:
      - yugabyte-network

  yb-tserver-2:
    image: yugabytedb/yugabyte:latest
    container_name: yb-tserver-2
    command: [
      "/home/yugabyte/bin/yb-tserver",
      "--tserver_master_addrs=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-tserver-2:9100",
      "--enable_ysql=true",
      "--ysql_sequence_cache_minval=1",
      "--ysql_sequence_cache_maxval=1000",
      "--ysql_num_shards_per_tserver=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    ports:
      - "5435:5433"
      - "9044:9042"
      - "9002:9000"
    healthcheck:
      test: ["CMD", "/home/yugabyte/postgres/bin/pg_isready", "-h", "yb-tserver-2"]
      interval: 10s
      timeout: 5s
      retries: 10
    depends_on:
      - yb-master-0
      - yb-master-1
      - yb-master-2
    networks:
      - yugabyte-network

  yb-tserver-3:
    image: yugabytedb/yugabyte:latest
    container_name: yb-tserver-3
    command: [
      "/home/yugabyte/bin/yb-tserver",
      "--tserver_master_addrs=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-tserver-3:9100",
      "--enable_ysql=true",
      "--ysql_sequence_cache_minval=1",
      "--ysql_sequence_cache_maxval=1000",
      "--ysql_num_shards_per_tserver=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    ports:
      - "5436:5433"
      - "9045:9042"
      - "9003:9000"
    healthcheck:
      test: ["CMD", "/home/yugabyte/postgres/bin/pg_isready", "-h", "yb-tserver-3"]
      interval: 10s
      timeout: 5s
      retries: 10
    depends_on:
      - yb-master-0
      - yb-master-1
      - yb-master-2
    networks:
      - yugabyte-network

  yb-tserver-4:
    image: yugabytedb/yugabyte:latest
    container_name: yb-tserver-4
    command: [
      "/home/yugabyte/bin/yb-tserver",
      "--tserver_master_addrs=yb-master-0:7100,yb-master-1:7100,yb-master-2:7100",
      "--fs_data_dirs=/home/yugabyte/data",
      "--rpc_bind_addresses=yb-tserver-4:9100",
      "--enable_ysql=true",
      "--ysql_sequence_cache_minval=1",
      "--ysql_sequence_cache_maxval=1000",
      "--ysql_num_shards_per_tserver=2",
      "--rpc_connection_timeout_ms=15000"
    ]
    ports:
      - "5437:5433"
      - "9046:9042"
      - "9004:9000"
    healthcheck:
      test: ["CMD", "/home/yugabyte/postgres/bin/pg_isready", "-h", "yb-tserver-4"]
      interval: 10s
      timeout: 5s
      retries: 10
    depends_on:
      - yb-master-0
      - yb-master-1
      - yb-master-2
    networks:
      - yugabyte-network

networks:
  yugabyte-network:
    driver: bridge

volumes:
  yugaware-data:
