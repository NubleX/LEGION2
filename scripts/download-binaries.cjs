#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');
const os = require('os');

// Configuration
const BINARIES_DIR = path.join(__dirname, '..', 'src-tauri', 'bin');
const TEMP_DIR = path.join(__dirname, '..', 'temp-downloads');

// Binary download configurations
const NMAP_VERSIONS = {
    windows: {
        url: 'https://nmap.org/dist/nmap-7.97.zip',
        filename: 'nmap-7.97.zip',
        executable: 'nmap.exe',
        extractPath: 'nmap.exe'  // Assume nmap.exe is at root of zip
    },
    linux: {
        // For Linux, we'll download from official repositories or compile
        url: 'https://nmap.org/dist/nmap-7.97.tar.bz2',
        filename: 'nmap-7.97.tar.bz2',
        executable: 'nmap',
        needsCompile: true
    }
};

const MASSCAN_CONFIG = {
    windows: {
        // For Windows, we'll also compile from source as pre-built binaries may not be available
        url: 'https://github.com/robertdavidgraham/masscan/archive/refs/tags/1.3.2.zip',
        filename: 'masscan-1.3.2-source.zip',
        executable: 'masscan.exe',
        needsCompile: true,  // Will need MinGW or Visual Studio
        fallbackMessage: 'Masscan compilation requires MinGW or Visual Studio on Windows'
    },
    linux: {
        // Masscan needs to be compiled from source
        url: 'https://github.com/robertdavidgraham/masscan/archive/refs/tags/1.3.2.zip',
        filename: 'masscan-1.3.2.zip',
        executable: 'masscan',
        needsCompile: true
    }
};

function detectPlatform() {
    const platform = os.platform();
    const arch = os.arch();
    
    if (platform === 'win32') {
        return 'windows';
    } else if (platform === 'linux') {
        return 'linux';
    } else if (platform === 'darwin') {
        return 'linux'; // Use linux config for macOS, will compile from source
    } else {
        throw new Error(`Unsupported platform: ${platform}`);
    }
}

function ensureDirectory(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`Created directory: ${dir}`);
    }
}

function downloadFile(url, destination) {
    return new Promise((resolve, reject) => {
        console.log(`Downloading ${url}...`);
        const file = fs.createWriteStream(destination);
        
        https.get(url, (response) => {
            if (response.statusCode === 302 || response.statusCode === 301) {
                // Handle redirects
                file.close();
                fs.unlinkSync(destination);
                return downloadFile(response.headers.location, destination)
                    .then(resolve)
                    .catch(reject);
            }
            
            if (response.statusCode !== 200) {
                file.close();
                fs.unlinkSync(destination);
                return reject(new Error(`Download failed with status ${response.statusCode}`));
            }
            
            response.pipe(file);
            
            file.on('finish', () => {
                file.close();
                console.log(`Downloaded: ${path.basename(destination)}`);
                resolve();
            });
            
            file.on('error', (err) => {
                file.close();
                fs.unlinkSync(destination);
                reject(err);
            });
        }).on('error', (err) => {
            file.close();
            if (fs.existsSync(destination)) {
                fs.unlinkSync(destination);
            }
            reject(err);
        });
    });
}

function extractZip(zipFile, extractTo, targetFile = null) {
    console.log(`Extracting ${zipFile}...`);
    
    try {
        if (os.platform() === 'win32') {
            // Use PowerShell on Windows
            execSync(`powershell -command "Expand-Archive -Path '${zipFile}' -DestinationPath '${extractTo}' -Force"`, {
                stdio: 'inherit'
            });
        } else {
            // Use unzip on Unix-like systems
            execSync(`unzip -o "${zipFile}" -d "${extractTo}"`, {
                stdio: 'inherit'
            });
        }
        console.log(`Extracted to: ${extractTo}`);
        
        if (targetFile) {
            const extractedFile = path.join(extractTo, targetFile);
            if (fs.existsSync(extractedFile)) {
                return extractedFile;
            } else {
                console.warn(`Target file not found: ${extractedFile}`);
                // List contents to help debug
                const contents = fs.readdirSync(extractTo, { recursive: true });
                console.log('Archive contents:', contents);
                return null;
            }
        }
        
        return extractTo;
    } catch (error) {
        console.error(`Extraction failed: ${error.message}`);
        return null;
    }
}

function compileNmap(sourceDir) {
    console.log('Compiling nmap from source...');
    const buildDir = path.join(sourceDir, 'nmap-7.94');
    
    try {
        process.chdir(buildDir);
        
        // Configure and build
        execSync('./configure --prefix=/usr/local', { stdio: 'inherit' });
        execSync('make', { stdio: 'inherit' });
        
        const nmapBinary = path.join(buildDir, 'nmap');
        if (fs.existsSync(nmapBinary)) {
            return nmapBinary;
        } else {
            throw new Error('Compiled nmap binary not found');
        }
    } catch (error) {
        console.error(`Nmap compilation failed: ${error.message}`);
        return null;
    }
}

function compileMasscan(sourceDir) {
    console.log('Compiling masscan from source...');
    const buildDir = path.join(sourceDir, 'masscan-1.3.2');
    
    try {
        process.chdir(buildDir);
        
        // Build masscan
        execSync('make', { stdio: 'inherit' });
        
        const masscanBinary = path.join(buildDir, 'bin', 'masscan');
        if (fs.existsSync(masscanBinary)) {
            return masscanBinary;
        } else {
            throw new Error('Compiled masscan binary not found');
        }
    } catch (error) {
        console.error(`Masscan compilation failed: ${error.message}`);
        return null;
    }
}

async function downloadNmap(platform) {
    const config = NMAP_VERSIONS[platform];
    if (!config) {
        throw new Error(`No nmap configuration for platform: ${platform}`);
    }
    
    const downloadPath = path.join(TEMP_DIR, config.filename);
    const targetPath = path.join(BINARIES_DIR, config.executable);
    
    // Skip if already exists
    if (fs.existsSync(targetPath)) {
        console.log(`Nmap already exists: ${targetPath}`);
        return targetPath;
    }
    
    // Download
    await downloadFile(config.url, downloadPath);
    
    let binaryPath;
    
    if (config.needsCompile) {
        // Extract and compile
        const extractDir = path.join(TEMP_DIR, 'nmap-extract');
        extractZip(downloadPath, extractDir);
        binaryPath = compileNmap(extractDir);
    } else {
        // Extract pre-built binary
        const extractDir = path.join(TEMP_DIR, 'nmap-extract');
        const extractedBinary = extractZip(downloadPath, extractDir, config.extractPath);
        binaryPath = extractedBinary;
    }
    
    if (!binaryPath || !fs.existsSync(binaryPath)) {
        throw new Error('Failed to obtain nmap binary');
    }
    
    // Copy to binaries directory
    fs.copyFileSync(binaryPath, targetPath);
    
    // Set executable permissions on Unix-like systems
    if (platform !== 'windows') {
        fs.chmodSync(targetPath, 0o755);
    }
    
    console.log(`Nmap ready: ${targetPath}`);
    return targetPath;
}

async function downloadMasscan(platform) {
    const config = MASSCAN_CONFIG[platform];
    if (!config) {
        throw new Error(`No masscan configuration for platform: ${platform}`);
    }
    
    const downloadPath = path.join(TEMP_DIR, config.filename);
    const targetPath = path.join(BINARIES_DIR, config.executable);
    
    // Skip if already exists
    if (fs.existsSync(targetPath)) {
        console.log(`Masscan already exists: ${targetPath}`);
        return targetPath;
    }
    
    // Download
    await downloadFile(config.url, downloadPath);
    
    let binaryPath;
    
    if (config.needsCompile) {
        // Extract and compile
        const extractDir = path.join(TEMP_DIR, 'masscan-extract');
        extractZip(downloadPath, extractDir);
        binaryPath = compileMasscan(extractDir);
    } else {
        // Extract pre-built binary
        const extractDir = path.join(TEMP_DIR, 'masscan-extract');
        const extractedBinary = extractZip(downloadPath, extractDir, config.extractPath);
        binaryPath = extractedBinary;
    }
    
    if (!binaryPath || !fs.existsSync(binaryPath)) {
        throw new Error('Failed to obtain masscan binary');
    }
    
    // Copy to binaries directory
    fs.copyFileSync(binaryPath, targetPath);
    
    // Set executable permissions on Unix-like systems
    if (platform !== 'windows') {
        fs.chmodSync(targetPath, 0o755);
    }
    
    console.log(`Masscan ready: ${targetPath}`);
    return targetPath;
}

async function main() {
    console.log('LEGION2 Binary Download Script');
    console.log('==============================');
    
    try {
        const platform = detectPlatform();
        console.log(`Detected platform: ${platform}`);
        
        // Ensure directories exist
        ensureDirectory(TEMP_DIR);
        ensureDirectory(BINARIES_DIR);
        
        // Download binaries
        console.log('\nDownloading nmap...');
        await downloadNmap(platform);
        
        console.log('\nDownloading masscan...');
        await downloadMasscan(platform);
        
        // Clean up temp directory
        console.log('\nCleaning up temporary files...');
        if (fs.existsSync(TEMP_DIR)) {
            fs.rmSync(TEMP_DIR, { recursive: true, force: true });
        }
        
        console.log('\n✅ Binary download completed successfully!');
        console.log(`Binaries are now available in: ${BINARIES_DIR}`);
        
        // List downloaded files
        const files = fs.readdirSync(BINARIES_DIR);
        console.log('\nDownloaded binaries:');
        files.forEach(file => {
            const filePath = path.join(BINARIES_DIR, file);
            const stats = fs.statSync(filePath);
            console.log(`  - ${file} (${Math.round(stats.size / 1024)}KB)`);
        });
        
    } catch (error) {
        console.error('\n❌ Binary download failed:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { main, downloadNmap, downloadMasscan };