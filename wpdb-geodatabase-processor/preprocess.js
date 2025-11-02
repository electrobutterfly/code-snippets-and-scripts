import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration - UPDATE THESE PATHS TO MATCH YOUR ACTUAL FILE LOCATIONS
const config = {
    // Input files - UPDATE THESE PATHS!
    inputFiles: {
        af: './geodata/wdpa_af.geojson',
        as: './geodata/wdpa_as.geojson', 
        eu: './geodata/wdpa_eu.geojson',
        na: './geodata/wdpa_na.geojson',
        wa: './geodata/wdpa_wa.geojson'
    },
    
    // Output settings
    output: {
        chunks: './data/processed/chunks/',
        maxChunkSize: 50000,
        featuresPerChunk: 100 // Increased for better performance
    }
};

class GeoJSONProcessor {
    constructor(region, options = {}) {
        this.region = region;
        this.featureCount = 0;
        this.currentChunk = [];
        this.chunkIndex = 0;
    }

    processFeature(feature) {
        // Skip invalid features
        if (!feature || !feature.type || feature.type !== 'Feature') {
            return;
        }

        this.featureCount++;
        
        // Optimize the feature
        const optimizedFeature = this.optimizeFeature(feature);
        this.currentChunk.push(optimizedFeature);

        // Write chunk if it reaches size limit
        if (this.currentChunk.length >= config.output.featuresPerChunk) {
            this.writeChunk();
        }
    }

    finish() {
        if (this.currentChunk.length > 0) {
            this.writeChunk();
        }
        console.log(`Processed ${this.featureCount} features for ${this.region}`);
    }

    optimizeFeature(feature) {
        // Create a clean, optimized feature
        return {
            type: 'Feature',
            geometry: feature.geometry ? this.simplifyGeometry(feature.geometry) : null,
            properties: this.optimizeProperties(feature.properties),
            id: feature.id || `${this.region}_${this.featureCount}`
        };
    }

    simplifyGeometry(geometry) {
        if (!geometry || !geometry.coordinates) return geometry;
        
        // Only reduce precision, don't remove points for now
        const processCoordinates = (coords) => {
            if (Array.isArray(coords[0]) && Array.isArray(coords[0][0])) {
                // Nested arrays (polygons, multi-polygons)
                return coords.map(ring => processCoordinates(ring));
            } else if (Array.isArray(coords[0])) {
                // Array of coordinates (line string, polygon ring)
                return coords.map(coord => [
                    Math.round(coord[0] * 100000) / 100000, // ~1m precision
                    Math.round(coord[1] * 100000) / 100000
                ]);
            } else {
                // Single coordinate
                return [
                    Math.round(coords[0] * 100000) / 100000,
                    Math.round(coords[1] * 100000) / 100000
                ];
            }
        };

        return {
            type: geometry.type,
            coordinates: processCoordinates(geometry.coordinates)
        };
    }

    optimizeProperties(properties) {
        if (!properties) return {};
        
        // Keep only essential properties
        const essential = {};
        
        // WDPA core fields - adjust based on your actual field names
        if (properties.NAME !== undefined) essential.name = properties.NAME;
        if (properties.DESIG !== undefined) essential.designation = properties.DESIG;
        if (properties.DESIG_ENG !== undefined) essential.designation_en = properties.DESIG_ENG;
        if (properties.IUCN_CAT !== undefined) essential.iucn_category = properties.IUCN_CAT;
        if (properties.ISO3 !== undefined) essential.country = properties.ISO3;
        if (properties.REP_AREA !== undefined) essential.area = properties.REP_AREA;
        if (properties.WDPAID !== undefined) essential.wdpaid = properties.WDPAID;
        if (properties.MARINE !== undefined) essential.marine = properties.MARINE;
        
        // Try alternative field names
        if (!essential.name && properties.name !== undefined) essential.name = properties.name;
        if (!essential.designation && properties.designation !== undefined) essential.designation = properties.designation;
        
        return essential;
    }

    writeChunk() {
        const chunk = {
            type: 'FeatureCollection',
            features: this.currentChunk,
            metadata: {
                region: this.region,
                chunk: this.chunkIndex,
                totalFeatures: this.currentChunk.length
            }
        };

        const filename = `${this.region}_chunk_${this.chunkIndex}.json`;
        const filepath = path.join(config.output.chunks, filename);
        
        // Ensure directory exists
        const dir = path.dirname(filepath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        
        fs.writeFileSync(filepath, JSON.stringify(chunk));
        
        console.log(`Written chunk ${this.chunkIndex} for ${this.region} with ${this.currentChunk.length} features`);
        
        this.currentChunk = [];
        this.chunkIndex++;
    }
}

// Process GeoJSON file that's a single FeatureCollection
async function processFeatureCollectionFile(regionCode, filePath, processor) {
    console.log(`Reading FeatureCollection from ${filePath}...`);
    
    try {
        // For large files, we need to stream and parse carefully
        const fileStream = fs.createReadStream(filePath, { encoding: 'utf8' });
        let data = '';
        let featuresFound = 0;

        for await (const chunk of fileStream) {
            data += chunk;
            
            // Try to find and extract features as we read
            const featureMatch = data.match(/"features"\s*:\s*\[([\s\S]*?)\](?=,?\s*[}\]])/);
            if (featureMatch) {
                // We found the features array, now extract individual features
                const featuresStr = featureMatch[1];
                
                // Simple approach: look for feature objects
                let featureStart = -1;
                let bracketCount = 0;
                let inString = false;
                let escapeNext = false;
                
                for (let i = 0; i < featuresStr.length; i++) {
                    const char = featuresStr[i];
                    
                    if (escapeNext) {
                        escapeNext = false;
                        continue;
                    }
                    
                    if (char === '\\') {
                        escapeNext = true;
                        continue;
                    }
                    
                    if (char === '"') {
                        inString = !inString;
                        continue;
                    }
                    
                    if (!inString) {
                        if (char === '{' && bracketCount === 0) {
                            featureStart = i;
                            bracketCount = 1;
                        } else if (char === '{') {
                            bracketCount++;
                        } else if (char === '}') {
                            bracketCount--;
                            if (bracketCount === 0 && featureStart !== -1) {
                                // Found a complete feature
                                const featureJson = featuresStr.substring(featureStart, i + 1);
                                try {
                                    const feature = JSON.parse(featureJson);
                                    processor.processFeature(feature);
                                    featuresFound++;
                                    
                                    if (featuresFound % 1000 === 0) {
                                        console.log(`Processed ${featuresFound} features for ${regionCode}...`);
                                    }
                                } catch (e) {
                                    console.log('Error parsing feature:', e.message);
                                }
                                featureStart = -1;
                            }
                        }
                    }
                }
                
                break; // We processed the features array, no need to continue
            }
            
            // Prevent memory issues with very large files
            if (data.length > 10000000) { // 10MB
                console.log('File too large for this method, trying alternative approach...');
                break;
            }
        }
        
        return featuresFound;
        
    } catch (error) {
        console.error(`Error reading file ${filePath}:`, error);
        return 0;
    }
}

// Alternative method: Use line-by-line reading for newline-delimited JSON
async function processLineDelimitedFile(regionCode, filePath, processor) {
    console.log(`Trying line-delimited reading for ${filePath}...`);
    
    const fileStream = fs.createReadStream(filePath, { encoding: 'utf8' });
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    let featuresFound = 0;

    for await (const line of rl) {
        const trimmed = line.trim();
        if (trimmed.length === 0) continue;
        
        // Skip FeatureCollection header/footer
        if (trimmed.includes('"FeatureCollection"')) continue;
        if (trimmed.includes('"features"')) continue;
        if (trimmed === '[' || trimmed === ']' || trimmed === '{' || trimmed === '}') continue;
        
        // Remove trailing comma if present
        let cleanLine = trimmed;
        if (cleanLine.endsWith(',')) {
            cleanLine = cleanLine.slice(0, -1);
        }
        
        // Try to parse as feature
        if (cleanLine.startsWith('{') && cleanLine.endsWith('}')) {
            try {
                const feature = JSON.parse(cleanLine);
                if (feature.type === 'Feature') {
                    processor.processFeature(feature);
                    featuresFound++;
                    
                    if (featuresFound % 1000 === 0) {
                        console.log(`Processed ${featuresFound} features for ${regionCode}...`);
                    }
                }
            } catch (e) {
                // Not a valid feature JSON, skip
            }
        }
    }
    
    return featuresFound;
}

// Process a single region
async function processRegion(regionCode) {
    console.log(`\n=== Processing ${regionCode} ===`);
    
    const inputFile = config.inputFiles[regionCode];
    console.log(`Input file: ${inputFile}`);
    
    if (!fs.existsSync(inputFile)) {
        console.log(`❌ File not found: ${inputFile}`);
        console.log(`Current working directory: ${process.cwd()}`);
        console.log(`Please check the file path in config`);
        return;
    }

    // Check file size
    const stats = fs.statSync(inputFile);
    console.log(`File size: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);

    // Create output directory
    if (!fs.existsSync(config.output.chunks)) {
        fs.mkdirSync(config.output.chunks, { recursive: true });
    }

    const processor = new GeoJSONProcessor(regionCode);
    let featuresFound = 0;

    try {
        // First, try to read the file as a complete GeoJSON to understand its structure
        const sampleData = fs.readFileSync(inputFile, 'utf8', 0, 5000);
        console.log(`File sample (first 200 chars): ${sampleData.substring(0, 200)}...`);

        if (sampleData.includes('"FeatureCollection"')) {
            console.log('Detected FeatureCollection format');
            featuresFound = await processFeatureCollectionFile(regionCode, inputFile, processor);
        } else if (sampleData.includes('"type":"Feature"')) {
            console.log('Detected line-delimited features format');
            featuresFound = await processLineDelimitedFile(regionCode, inputFile, processor);
        } else {
            console.log('Unknown format, trying line-delimited approach...');
            featuresFound = await processLineDelimitedFile(regionCode, inputFile, processor);
        }

        processor.finish();
        console.log(`✅ Finished processing ${regionCode}. Total features: ${featuresFound}`);
        
    } catch (error) {
        console.error(`❌ Error processing ${regionCode}:`, error);
    }
}

// Process all regions
async function processAllRegions() {
    console.log('Starting GeoJSON preprocessing...');
    console.log('Regions to process:', Object.keys(config.inputFiles));
    console.log('Current directory:', process.cwd());
    
    for (const region of Object.keys(config.inputFiles)) {
        await processRegion(region);
    }
    
    console.log('\n=== All regions processed! ===');
}

// Simple test function to check file structure
async function testFileStructure() {
    console.log('\n=== Testing file structure ===');
    
    for (const [region, filePath] of Object.entries(config.inputFiles)) {
        if (fs.existsSync(filePath)) {
            console.log(`\n${region}: ${filePath}`);
            try {
                const sample = fs.readFileSync(filePath, 'utf8', 0, 500);
                console.log(`First 500 chars: ${sample}`);
                console.log(`Contains "FeatureCollection": ${sample.includes('FeatureCollection')}`);
                console.log(`Contains "features": ${sample.includes('features')}`);
                console.log(`Contains "Feature": ${sample.includes('"type":"Feature"')}`);
            } catch (e) {
                console.log(`Error reading: ${e.message}`);
            }
        } else {
            console.log(`\n${region}: FILE NOT FOUND at ${filePath}`);
        }
    }
}

// Run if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    // Check if we should test first
    if (process.argv.includes('--test')) {
        testFileStructure();
    } else {
        processAllRegions().catch(console.error);
    }
}

export { processAllRegions, processRegion, testFileStructure };
