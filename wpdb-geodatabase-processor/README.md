# Process WPDB Geodatabase Files

## Description

Written for node.js.
The goal is to process and split the **huge geodatabase files in "geojson format"** which can be as big as 10GB each,
or even bigger, into smaller json chunks which can be handled better by smaller servers (<= 8GB)
without crashing them, for easy injection as layers into maps. The project is set to use ES modules.

<u>**Was it does:**</u>
**preprocessor.js** reads the geodatabase files in "geojson" format , splits them into
smaller json files and places them into the "./data/chunks" directory.
At least that is what it should do. 😄

**file-inspector.js** analyzes the format of the geodatabase file and outputs any
information found the following way:
FileSize
Features
Geometries
Geometry types (MultiPolygon)
Sample properties (type, name, crs, DESIG_ENG, IUCN_CAT, NAME, STATUS, WDPAID)
Coordinates (avg, max)

## Usage preprocessor.js

Make sure the following directory structure exists.

```
**your-project-root**/
└── preprocess/ 
         ├── preprocessor.js
         ├── file-inspector.js
         └── config.js
     └─ data/
          ├── raw/ (your 25+GB GeoJSON files)
          └── processed/chunks (optimized regional chunks)
```


Place your GeoJSON files in data/raw/ with the exact names:

wdpa_af.geojson
wdpa_as.geojson
wdpa_eu.geojson
wdpa_na.geojson
wdpa_wa.geojson
wdpa_sa.geojson

If the actual location of your "geojson" files varies, you can configure the location in config.js as needed.

## Install dependencies

**node.js**

```bash
node --version    # Should show v18.x.x or higher
```

**npm**

```bash
npm --version     # Should show 8.x.x or **higher**
```



```bash
# On Ubuntu/Debian:
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# On CentOS/RHEL/Fedora:
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs  # or dnf on newer versions

# Or using Node Version Manager (recommended):
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 18
nvm use 18
```



## Run preprocessing

🚀 **Execution Steps**
Run the preprocessor from your project root (Go and grab a coffee or have some lunch, this will take a while for 25+GB)

```bash
bash
cd "your-project-root"
node preprocessor.js
```

Run like this if you are running out of memory (can be adjusted, use 16384 for 16GB, and so on:

```bash
bash
free -h  # Check available memory
node --max-old-space-size=8192 preprocessor.js
```

Or if you still run out of memory try proceesing by regions

```bash
node --max-old-space-size=8192 preprocessor.js --region as
node --max-old-space-size=8192 preprocessor.js --region na
node --max-old-space-size=8192 preprocessor.js --region eu
node --max-old-space-size=8192 preprocessor.js --region wa
```



## Issues and bugs

Please report any issues and bugs found at the [Issue Tracker](https://github.com/electrobutterfly/code-snippets-and-scripts/issues)



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

*See the [LICENSE](./LICENSE) file for full terms.*



## Project status

Software, Code snippets or scripts might be added from time to time as my work progress goes on
and I decide to make the code public for everyone to use.
