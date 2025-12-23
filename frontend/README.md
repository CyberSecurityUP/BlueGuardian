# BlueGuardian AI - Web UI

Modern, responsive web interface for BlueGuardian AI security analysis framework.

## Features

- **Dashboard**: Real-time overview of analysis jobs, statistics, and system status
- **File Upload**: Drag-and-drop file upload with auto-detection
- **URL Analysis**: Network indicator analysis (IPs, URLs, domains)
- **Job Management**: Track and manage all analysis jobs
- **Detailed Results**: View comprehensive analysis results with IOCs and MITRE ATT&CK techniques
- **Report Export**: Download reports in HTML, PDF, or JSON formats
- **Settings**: System configuration and cost tracking

## Tech Stack

- **React 18** - Modern UI library
- **TypeScript** - Type-safe development
- **Vite** - Fast build tool
- **Tailwind CSS** - Utility-first CSS framework
- **React Router** - Client-side routing
- **TanStack Query** - Data fetching and caching
- **Recharts** - Beautiful charts and visualizations
- **Axios** - HTTP client
- **Lucide React** - Icon library

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- BlueGuardian AI backend running on `http://localhost:8000`

### Installation

```bash
# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Start development server
npm run dev
```

The application will be available at `http://localhost:3000`.

### Build for Production

```bash
# Build optimized production bundle
npm run build

# Preview production build
npm run preview
```

## Project Structure

```
frontend/
├── src/
│   ├── components/        # Reusable components
│   │   └── Layout.tsx    # Main layout with sidebar
│   ├── pages/            # Page components
│   │   ├── Dashboard.tsx       # Dashboard overview
│   │   ├── AnalysisPage.tsx    # File upload & analysis
│   │   ├── JobsPage.tsx        # Jobs list
│   │   ├── JobDetailsPage.tsx  # Job details & results
│   │   └── SettingsPage.tsx    # System settings
│   ├── services/         # API services
│   │   └── api.ts       # API client
│   ├── App.tsx          # Main app component
│   ├── main.tsx         # Entry point
│   └── index.css        # Global styles
├── index.html           # HTML template
├── vite.config.ts       # Vite configuration
├── tailwind.config.js   # Tailwind configuration
└── package.json         # Dependencies
```

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## Environment Variables

Create a `.env` file from `.env.example`:

```env
VITE_API_URL=http://localhost:8000/api/v1
```

## API Integration

The frontend communicates with the BlueGuardian AI backend via REST API:

- **Health Check**: `GET /api/v1/health`
- **System Status**: `GET /api/v1/status`
- **Upload & Analyze**: `POST /api/v1/analyze/file`
- **URL Analysis**: `POST /api/v1/analyze/url`
- **List Jobs**: `GET /api/v1/jobs`
- **Job Details**: `GET /api/v1/jobs/{job_id}`
- **Job Results**: `GET /api/v1/jobs/{job_id}/result`
- **Download Report**: `GET /api/v1/jobs/{job_id}/report/{format}`

## Development

### Adding New Pages

1. Create page component in `src/pages/`
2. Add route in `src/App.tsx`
3. Add navigation link in `src/components/Layout.tsx`

### Adding New API Endpoints

1. Add TypeScript types in `src/services/api.ts`
2. Add API function to `apiService` object
3. Use with TanStack Query in components

## Contributing

See the main project README for contribution guidelines.

## License

MIT License - See LICENSE file for details
