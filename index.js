const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { auth } = require('express-oauth2-jwt-bearer');

const app = express();
const PORT = 3000;

// 1. CORS Configuration
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// The base directory you want to manage
const STORAGE_ROOT = path.resolve(__dirname, 'storage');
if (!fs.existsSync(STORAGE_ROOT)) {
    fs.mkdirSync(STORAGE_ROOT, { recursive: true });
}

function resolveSafePath(userPath = '') {
    const safePath = path.resolve(STORAGE_ROOT, userPath.replace(/^(\.\.(\/|\\|$))+/, ''));
    if (!safePath.startsWith(STORAGE_ROOT)) {
        throw new Error('Access denied: Unauthorized directory path.');
    }
    return safePath;
}

// -------------------------------------------------------------
// Security Middleware: Auth0 JWT Validation
// -------------------------------------------------------------
// This automatically fetches Auth0 public keys and verifies the token signature
const authenticateToken = auth({
    audience: 'http://localhost:3000',
    issuerBaseURL: 'https://dev-0hhegyynizwv18yv.us.auth0.com/',
    tokenSigningAlg: 'RS256'
});

// -------------------------------------------------------------
// Security Middleware: Role-Based Access Control (RBAC)
// -------------------------------------------------------------
function requireAdmin(req, res, next) {
    // The express-oauth2-jwt-bearer library attaches the decoded token to req.auth
    const payload = req.auth.payload;

    // Check for the groups claim (Auth0 sometimes requires custom claims to be namespaced URIs)
    // Adjust 'groups' to match exactly how you named the claim in the Auth0/Okta dashboard
    const userGroups = payload['groups'] || payload['http://filebridge.com/groups'] || [];

    if (!userGroups.includes('FileBridge_Admins')) {
        return res.status(403).json({ error: 'Access denied: Requires Admin privileges.' });
    }

    next();
}

// -------------------------------------------------------------
// 1. Read-Only Routes (Any authenticated user)
// -------------------------------------------------------------
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const relativePath = req.query.path || '';
        const targetDir = resolveSafePath(relativePath);
        const entries = await fs.promises.readdir(targetDir, { withFileTypes: true });

        const fileList = await Promise.all(
            entries.map(async (entry) => {
                const itemPath = path.join(targetDir, entry.name);
                let stats = null;
                try { stats = await fs.promises.stat(itemPath); } catch {}

                return {
                    name: entry.name,
                    isDirectory: entry.isDirectory(),
                    size: stats ? stats.size : 0,
                    updatedAt: stats ? stats.mtime : null,
                    relativePath: path.relative(STORAGE_ROOT, itemPath)
                };
            })
        );
        res.json({ currentPath: relativePath, items: fileList });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.get('/api/download', authenticateToken, (req, res) => {
    try {
        const relativePath = req.query.path;
        if (!relativePath) return res.status(400).json({ error: 'Path is required.' });

        const filePath = resolveSafePath(relativePath);
        if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
            return res.status(404).json({ error: 'File not found.' });
        }
        res.download(filePath);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// -------------------------------------------------------------
// 2. Write Routes (Strictly Admins Only)
// -------------------------------------------------------------
const storageEngine = multer.diskStorage({
    destination: (req, file, cb) => {
        try {
            const destinationFolder = resolveSafePath(req.body.targetPath || '');
            cb(null, destinationFolder);
        } catch (err) {
            cb(err);
        }
    },
    filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage: storageEngine });

// Note the middleware chain: Authenticate first -> Verify Admin -> Handle Upload
app.post('/api/upload', authenticateToken, requireAdmin, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
    res.json({ message: 'File uploaded successfully', file: req.file.originalname });
});

app.post('/api/mkdir', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { targetPath, folderName } = req.body;
        if (!folderName) return res.status(400).json({ error: 'Folder name is required.' });

        const parentDir = resolveSafePath(targetPath || '');
        const newDirPath = path.join(parentDir, folderName);

        await fs.promises.mkdir(newDirPath, { recursive: false });
        res.json({ message: 'Folder created successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.delete('/api/delete', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const relativePath = req.query.path;
        if (!relativePath) return res.status(400).json({ error: 'Path is required.' });

        const targetPath = resolveSafePath(relativePath);
        if (targetPath === STORAGE_ROOT) {
            return res.status(403).json({ error: 'Cannot delete the storage root directory.' });
        }

        const stat = await fs.promises.stat(targetPath);
        if (stat.isDirectory()) {
            await fs.promises.rm(targetPath, { recursive: true, force: true });
        } else {
            await fs.promises.unlink(targetPath);
        }
        res.json({ message: 'Item deleted successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Remote File Manager backend running at http://localhost:${PORT}`);
});