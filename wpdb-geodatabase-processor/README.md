# Process WPDB Geodatabase geojson files

## Description

**Written for node.js.**
The goal is to process and split the **huge geodatabase files in "geojson format"** which can be as big as 10GB each, or even much bigger, without crashing the script running out of memory. It splits hem into smaller json chunks which then can be handled better for easy injection as layers into maps by web applications.

<u>**Was it does:**</u>
**preprocessor.js** reads the huge geodatabase geojson file, splits them into smaller json files and places small, optimized in regional .json chunks into the "./data/chunks" directory.
At least that is what it should do. 😄

**file-inspector.js** analyzes the format of the geodatabase files and outputs any
information found the following way:
FileSize
Features
Geometries
Geometry types (MultiPolygon)
Sample properties (type, name, crs, DESIG_ENG, IUCN_CAT, NAME, STATUS, WDPAID)
Coordinates (avg, max)

**Make sure the following directory structure exists.**

```
📁  **wpdb-geodatabase-processor**/
│
├── 🔧 preprocessor.js
├── 🔍 file-inspector.js  
├── ⚙️ config.js
│
└── 📁 data/
    ├── 📁 raw/
    │   └── 🌍 Place all *.geojson files here   
    │
    ├── 📁 chunks/
    │   └── 📁 */ (This is where the processed json chunks are placed) 
    │
    └── 📁 reports/ (script generated reports will be placed here)
        ├── 📊 processing-report.html
        └── 📊 inspection-report.html
```

Place your GeoJSON files in data/raw/ with the exact names:

wdpa_af.geojson
wdpa_as.geojson
wdpa_eu.geojson
wdpa_na.geojsongit push github-remote
wdpa_wa.geojson
wdpa_sa.geojson

The actual path to your "geojson" files can configured in config.js .



## Install dependencies

**node.js**
Note that we are using "ES modules" (import/export) so we need to have a Node.js version that supports them and "top-level await" support.(version 14.8.0+ recommended).

```bash
node --version    # Should show v14.8.x or higher
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

****

## Usage file-inspector.js

You should run this first. The script will take a while to execute. You can configure html or console output but html output
will be much more extensive. This will give you a rough idea what to expect in the geojson files. Go and grab a coffee, **it will take a while**.
When finished, the script launches a webserver which can be accessed through your browser at [http://localhost:8081](http://localhost:8081).
Press Ctrl+C to stop the server.

```bash
node file-inspector.js
```




## Run preprocessing

🚀 **Execution Steps**
IF you love to fill your console up with thousands of lines, go for it. Otherwise make sure you select html output. You will get a nice formatted html page which you can access through your browser. Run the preprocessor from your project root (Go and grab another coffee or have some lunch, this will **take a while** for 15+GB)

```bash
node preprocessor.js
```

Run like this if you are running out of memory (can be adjusted, use 16384 for 16GB, and so on). If you set it too high and there is not
enough memory available, the script will simply crash.

```bash
free -h  # Check available memory
node --max-old-space-size=8192 preprocessor.js
```

Or if you still run out of memory try proceesing by regions

```bash
node --max-old-space-size=8192 preprocessor.js --region na
node --max-old-space-size=8192 preprocessor.js --region eu
...
```



## More Info

We are using the `global.gc` for garbage collection. This is available when running Node.js with the `--expose-gc` flag. The script will run without it, but the explicit garbage collection calls will be ignored.

So, to run the scripts with explicit garbage collection, for example you would do:

```bash
node --expose-gc preprocessor.js
# or
node --expose-gc --max-old-space-size=8192 preprocessor.js
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

<u>**The main restriction:**</u>

- You cannot sell a product **whose primary purpose is to resell this software's functionality**.

**For commercial sale licensing,** please contact: licensing@electrobutterfly.com

*See the [LICENSE](./LICENSE) file for full terms.*



## Project status

Software, Code snippets or scripts might be added from time to time as my work progress goes on
and I decide to make the code public.
