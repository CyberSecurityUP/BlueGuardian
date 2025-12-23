# Reports Directory (Deprecated)

**Note**: This directory is deprecated. Reports are now stored in `storage/reports/`.

This directory is kept for backward compatibility but should not be used for new deployments.

## Migration

If you have old reports in this directory, migrate them:

```bash
# Move old reports to new location
mv reports/* storage/reports/2025-01-15/

# Or use the migration script
python scripts/migrate_reports.py
```

## New Location

Reports are now organized in `storage/reports/` with the following structure:

```
storage/reports/
├── 2025-01-15/
│   ├── json/
│   ├── html/
│   └── pdf/
└── 2025-01-16/
    └── ...
```

See `storage/reports/README.md` for more information.
