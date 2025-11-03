# preprocess.js
# @copyright     (c) 2025 Klaus Simon
# @license       Custom Attribution-NonCommercial Sale License
# @description   Part of the wpdb-geodatabase-processor Project
# 
# Permission is granted to use, modify, and distribute this script
# for any purpose except commercial sale without explicit permission.
# Attribution must be retained in all copies.
# 
# For commercial licensing: mini5propilot@gmail.com
# Full license: LICENSE file in repository
#####################################################################
#####################################################################


import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const config = {
    inputFiles: {
        af: './data/raw/wdpa_af.geojson',
        as: './data/raw/wdpa_as.geojson',  // 2.3GB - PROCESS SEPARATELY 
        eu: './data/raw/wdpa_eu.geojson',  // 9GB - PROCESS SEPARATELY
        na: './data/raw/wdpa_na.geojson',  // 2.6GB - PROCESS SEPARATELY
        wa: './data/raw/wdpa_wa.geojson'
    },
    output: {
        chunks: './data/chunks/',
        featuresPerChunk: 50 // Smaller chunks for huge files
    }
};

class MemorySafeProcessor {
    constructor() {
        this.currentChunk = [];
        this.chunkIndex = 0;
        this.featureCount = 0;
    }

    // Simple optimization - just reduce precision
    optimizeFeature(feature) {
        if (!feature.geometry) return null;

        // Reduce coordinate precision
        const simplifyCoords = (coords) => {
            if (Array.isArray(coords[0]) && Array.isArray(coords[0][0])) {
                return coords.map(ring => simplifyCoords(ring));
            } else if (Array.isArray(coords[0])) {
                return coords.map(coord => [
                    Math.round(coord[0] * 100000) / 100000,
                    Math.round(coord[1] * 100000) / 100000
                ]);
            }
            return coords;
        };

        return {
            type: 'Feature',
            geometry: {
                type: feature.geometry.type,
                coordinates: simplifyCoords(feature.geometry.coordinates)
            },
            properties: {
                name: String(feature.properties?.NAME || '').substring(0, 100),
                designation: String(feature.properties?.DESIG || '').substring(0, 50),
                iucn: String(feature.properties?.IUCN_CAT || ''),
                country: String(feature.properties?.ISO3 || ''),
                area: Number(feature.properties?.REP_AREA || 0),
                wdpaid: String(feature.properties?.WDPAID || '')
            }
        };
    }

    writeChunk(regionCode, outputDir) {
        if (this.currentChunk.length === 0) return;

        const chunkData = {
            type: 'FeatureCollection',
            features: this.currentChunk,
            metadata: {
                region: regionCode,
                chunk: this.chunkIndex,
                count: this.currentChunk.length
            }
        };

        const filename = `chunk_${this.chunkIndex}.json`;
        const filepath = path.join(outputDir, filename);
        
        fs.writeFileSync(filepath, JSON.stringify(chunkData));
        
        const sizeKB = Buffer.byteLength(JSON.stringify(chunkData)) / 1024;
        console.log(`   Wrote ${filename} (${this.currentChunk.length} features, ${sizeKB.toFixed(1)}KB)`);
        
        // Clear memory immediately
        this.currentChunk = [];
        this.chunkIndex++;
    }

    async processRegion(regionCode) {
        console.log(`\n🔨 Processing ${regionCode}...`);
        
        const inputFile = path.join(__dirname, config.inputFiles[regionCode]);
        if (!fs.existsSync(inputFile)) {
            console.log(`❌ File not found: ${inputFile}`);
            return 0;
        }

        const stats = fs.statSync(inputFile);
        console.log(`   Size: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);

        const outputDir = path.join(__dirname, config.output.chunks, regionCode);
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        // Reset counters for new region
        this.currentChunk = [];
        this.chunkIndex = 0;
        this.featureCount = 0;

        return new Promise((resolve, reject) => {
            const fileStream = fs.createReadStream(inputFile, { 
                encoding: 'utf8',
                highWaterMark: 64 * 1024 // 64KB chunks
            });

            const rl = readline.createInterface({
                input: fileStream,
                crlfDelay: Infinity
            });

            let inFeatures = false;
            let currentFeature = '';
            let braceDepth = 0;
            let lineCount = 0;

            console.log('   Reading features...');

            rl.on('line', (line) => {
                lineCount++;
                const trimmed = line.trim();

                if (trimmed.includes('"features":') && trimmed.includes('[')) {
                    inFeatures = true;
                    return;
                }

                if (!inFeatures) return;

                if (trimmed === ']' || trimmed === '],' || trimmed === ']}') {
                    inFeatures = false;
                    // Write final chunk
                    this.writeChunk(regionCode, outputDir);
                    return;
                }

                for (let i = 0; i < trimmed.length; i++) {
                    const char = trimmed[i];

                    if (char === '{' && braceDepth === 0) {
                        currentFeature = '{';
                        braceDepth = 1;
                    } else if (char === '{' && braceDepth > 0) {
                        currentFeature += char;
                        braceDepth++;
                    } else if (char === '}' && braceDepth > 0) {
                        currentFeature += char;
                        braceDepth--;
                        
                        if (braceDepth === 0) {
                            try {
                                let cleanFeature = currentFeature;
                                if (cleanFeature.endsWith(',')) {
                                    cleanFeature = cleanFeature.slice(0, -1);
                                }
                                
                                const feature = JSON.parse(cleanFeature);
                                if (feature.type === 'Feature' && feature.geometry) {
                                    const optimized = this.optimizeFeature(feature);
                                    if (optimized) {
                                        this.currentChunk.push(optimized);
                                        this.featureCount++;

                                        // Write chunk when full and clear memory
                                        if (this.currentChunk.length >= config.output.featuresPerChunk) {
                                            this.writeChunk(regionCode, outputDir);
                                        }
                                    }
                                }
                            } catch (error) {
                                // Skip parse errors
                            }
                            currentFeature = '';
                        }
                    } else if (braceDepth > 0) {
                        currentFeature += char;
                    }
                }

                // Progress and memory management
                if (lineCount % 50000 === 0) {
                    console.log(`   Read ${lineCount} lines, processed ${this.featureCount} features...`);
                    
                    // Force garbage collection if available
                    if (global.gc) {
                        global.gc();
                    }
                }
            });

            rl.on('close', () => {
                console.log(`✅ ${regionCode}: ${this.featureCount} features in ${this.chunkIndex} chunks`);
                resolve(this.featureCount);
            });

            rl.on('error', (error) => {
                reject(error);
            });
        });
    }

    async processSmallRegions() {
        console.log('🚀 Processing SMALL regions first...\n');
        
        // Process only small files first
        const smallRegions = ['wa', 'af']; // 9MB + 166MB
        let totalFeatures = 0;

        for (const region of smallRegions) {
            const count = await this.processRegion(region);
            totalFeatures += count;
        }

        console.log(`\n🎉 Small regions done: ${totalFeatures} features`);
        return totalFeatures;
    }

    async processLargeRegion(regionCode) {
        console.log(`\n⚠️  PROCESSING LARGE FILE: ${regionCode}`);
        console.log('   This may take a while...\n');
        
        // Increase memory limit for Node.js
        const count = await this.processRegion(regionCode);
        console.log(`✅ Large region ${regionCode} completed: ${count} features`);
        return count;
    }
}

// Run with increased memory limit and process one region at a time
async function main() {
    const processor = new MemorySafeProcessor();
    
    try {
        // Process small regions first
        await processor.processSmallRegions();
        
        // Ask before processing large files
        console.log('\n---');
        console.log('Next: Process large regions?');
        console.log('Run: preprocessor.js --region as');
        console.log('Run: preprocessor.js --region na'); 
        console.log('Run: preprocessor.js --region eu');
        console.log('---\n');
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

// Process specific region if specified
async function processSpecificRegion(regionCode) {
    const processor = new MemorySafeProcessor();
    
    // Set smaller chunk size for huge files
    if (['as', 'na', 'eu'].includes(regionCode)) {
        config.output.featuresPerChunk = 25;
    }
    
    await processor.processRegion(regionCode);
}

// Run with command line arguments
if (process.argv.includes('--region')) {
    const regionIndex = process.argv.indexOf('--region') + 1;
    const regionCode = process.argv[regionIndex];
    
    if (regionCode && config.inputFiles[regionCode]) {
        console.log(`🎯 Processing specific region: ${regionCode}`);
        processSpecificRegion(regionCode).catch(console.error);
    } else {
        console.log('❌ Invalid region. Use: --region wa|af|as|na|eu');
    }
} else {
    // Run normally (small regions only)
    main().catch(console.error);
}
