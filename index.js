const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = 3000;

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// 🔒 SECURITY: Change this to a long, random string!
const JWT_SECRET = 'super-secret-development-key-change-me';

// Set up your admin credentials.
// We hash the password on startup so it isn't sitting in plain text in memory.
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'thisShouldBeEncryptedPasswordDoNotForgetToChangeThisEverySixMonths'; // Change this!
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);

// The base directory on your laptop you want to manage
const STORAGE_ROOT = path.resolve(__dirname, 'storage');

// Ensure the storage root exists
if (!fs.existsSync(STORAGE_ROOT)) {
    fs.mkdirSync(STORAGE_ROOT, { recursive: true });
}

app.use(cors());
app.use(express.json());

// -------------------------------------------------------------
// Security Helper: Prevent Directory Traversal Attacks
// -------------------------------------------------------------
function resolveSafePath(userPath = '') {
    // Normalize and resolve the absolute path
    const safePath = path.resolve(STORAGE_ROOT, userPath.replace(/^(\.\.(\/|\\|$))+/, ''));

    // Ensure target path stays strictly inside STORAGE_ROOT
    if (!safePath.startsWith(STORAGE_ROOT)) {
        throw new Error('Access denied: Unauthorized directory path.');
    }

    return safePath;
}
// -------------------------------------------------------------
// Authentication: Login Route
// -------------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // Verify username and check if the password matches the hash
    if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
        // Generate a token that expires in 24 hours
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid username or password' });
    }
});

// -------------------------------------------------------------
// Security Helper: JWT Middleware
// -------------------------------------------------------------
function authenticateToken(req, res, next) {
    // The frontend must send the token in the "Authorization" header
    // Format: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6..."
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    // Verify the token hasn't been tampered with or expired
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
        }
        req.user = user; // Attach the user info to the request
        next(); // Pass control to the actual route handler
    });
}

// -------------------------------------------------------------
// 1. List Files and Directories
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

                try {
                    stats = await fs.promises.stat(itemPath);
                } catch {
                    // Ignore unreadable system files/links
                }

                return {
                    name: entry.name,
                    isDirectory: entry.isDirectory(),
                        size: stats ? stats.size : 0,
                        updatedAt: stats ? stats.mtime : null,
                        relativePath: path.relative(STORAGE_ROOT, itemPath)
                };
            })
        );

        res.json({
            currentPath: relativePath,
            items: fileList
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// -------------------------------------------------------------
// 2. Download File
// -------------------------------------------------------------
app.get('/api/download', authenticateToken,  (req, res) => {
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
// 3. Upload File
// -------------------------------------------------------------
const storageEngine = multer.diskStorage({
    destination: (req, file, callbackFunction) => {
        try {
            const destinationFolder = resolveSafePath(req.body.targetPath || '');
            callbackFunction(null, destinationFolder);
        } catch (err) {
            callbackFunction(err);
        }
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage: storageEngine });

app.post('/api/upload',  authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }
    res.json({ message: 'File uploaded successfully', file: req.file.originalname });
});

// -------------------------------------------------------------
// 4. Create Folder
// -------------------------------------------------------------
app.post('/api/mkdir',  authenticateToken, authenticateToken, async (req, res) => {
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

// -------------------------------------------------------------
// 5. Delete File or Directory
// -------------------------------------------------------------
app.delete('/api/delete',  authenticateToken, async (req, res) => {
    try {
        const relativePath = req.query.path;
        if (!relativePath) return res.status(400).json({ error: 'Path is required.' });

        const targetPath = resolveSafePath(relativePath);

        // Prevent accidental deletion of root storage folder
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
    console.log(`Managing directory: ${STORAGE_ROOT}`);
});
