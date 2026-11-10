# Migrations

Schema migrations use Flask-Migrate (Alembic). Initialise once, then migrate as models change:

```powershell
$env:FLASK_APP = "run.py"
flask db init        # creates migrations/ env files (first time only)
flask db migrate -m "initial schema"
flask db upgrade
```

For local development `python run.py` calls `db.create_all()` for convenience; use migrations for PostgreSQL production.
