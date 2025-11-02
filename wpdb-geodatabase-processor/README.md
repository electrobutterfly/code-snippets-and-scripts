# Process WPDB Geodatabase Files

## Description
The goal is to process and split the huge geodatabase files which can be as big as 10GB each,
into smaller json chunks which can be handled better by smaller servers without crashing them,
for easy injection into maps. The project is set to use ES modules

## Usage

Make sure the following directory structure exists. Was it does: It reads the geodatabase files,
splits them into smaller json files and places them into the "tiles" directory.
At least that is what it should do. 😄

your-project-root/ │ ├── preprocess/ │ ├── preprocess.js │ ├── tile-generator.js │ └── config.js └── data/ ├── raw/
(your 25+GB GeoJSON files) ├── processed/chunks (optimized regional chunks) └── tiles/ (vector tiles for map display)


Place your GeoJSON files in data/raw/ with the exact names:

wdpa_af.geojson
wdpa_as.geojson
wdpa_eu.geojson
wdpa_na.geojson
wdpa_wa.geojson


🚀 Execution Steps
Run the preprocessor from your project root:

bash
# Install dependencies
npm install express

# Run preprocessing (this will take a while for 25+GB) 
node preprocess/preprocess.js



## Authors and acknowledgment

© 2025 Klaus Simon.

## License

This project is licensed under the Custom Attribution-NonCommercial Sale License.

**You are free to:**
- Use, modify, and share the code for any purpose (personal, educational, commercial).
- Incorporate it into your own projects.

**The main restriction:**
- You cannot sell a product **whose primary purpose is to resell this software's functionality**.

**For commercial sale licensing,** please contact: mini5propilot@gmail.com

*See the [LICENSE](LICENSE) file for full terms.*

## Project status
Software, Code snippets or scripts might be added from time to time as my work progress goes on
and I decide to make the code public for everyone to use.
