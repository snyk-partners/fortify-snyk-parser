# Fortify SSC Snyk Parser Plugin
## Backgrond
This is a plugin for MicroFoucs Fortify Software Security Center that allows for parsing of scan results generated by `snyk test --json`.
The Fortify SSC is a software issue management center, and allows importing issues from external vendor code analyzers.
### Things to Note
* Information on Parser plugins and an example can be found [here](https://github.com/fortify/sample-parser)
* It follows the api as described [here](https://github.com/fortify/plugin-api)
* As per requirements, the plugin is compiled into a single JAR file that includes the library it uses: Gson.
## Releases
Latest release can be grabbed at the [releases page](https://github.com/snyk-partners/fortify-snyk-parser/releases).
In case you're interested in compiling it on your own, you only need maven installed, then follow:
### Compilation
```
git clone git@github.com:snyk-partners/fortify-snyk-parser.git
cd fortify-snyk-parser
mvn install
```
Then grab the file produced at:
`target/parser-x.x.x.jar`
## Installation
1. Open your browser and go to:
`http://127.0.0.1:8180/ssc/html/ssc/admin/parserplugins`
1. Click on `NEW` and acknowledge
1. Choose before-mentioned JAR file
1. Once uploaded, click on "Snyk Parser Plugin" line, then click `ENABLE` and acknowledge
1. Plugin should be installed now
## Usage
To use the Snyk Parser Plugin, cli scan results in `.json` format should be uploaded, in a special SSC `zip` file format.
1. Generate `scan.zip` scan results files. Inside any project execute:
```
snyk test --json > scan.json
echo "engineType=SNYK" > scan.info
zip -v scan.zip scan.json scan.info
```
1. Go to: `http://127.0.0.1:8180/ssc/html/ssc/version`
and click on the application you want to bind the scan results to.
If you don't have any, just create one (click `NEW APPLICATION` and then fill out info)
1. Click `ARTIFACTS` tab and there click `ARTIFACT`.
2. Click `ADD FILES` and select the `scan.zip` you just made. Then click `START UPLOAD`. `CLOSE` to close the window.
3. Once results were successfully processed, you should see status `Processing Complete` for the uploaded `scan.zip`.
4. Click on `AUDIT` tab at the top and you should see all issues reported by Snyk in the table.
5. Click on any row to reveal detailed information on issue.