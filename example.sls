CREATE USER replication:
  postgres_user.present:
    - name: replication
    - refresh_password: false
    - login: true
    - replication: true
  pg_scram.present:
    - name: replication
    - password: 'pa$$word'
    - require:
      - postgres_user: replication
