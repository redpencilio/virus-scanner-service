import { NamedNode, triple } from 'rdflib';
import bodyParser from 'body-parser';
import { LOG_INCOMING_DELTA } from './config';
import { app, errorHandler } from 'mu';
import { Delta } from './lib/delta';
import { existsSync } from 'node:fs';
import NodeClam from 'clamscan';

app.get('/', function (req, res) {
  res.send('Hello from virus-scanner-service');
});

app.post(
  '/delta',
  bodyParser.json({ limit: '50mb' }),
  async function (req, res) {
    try {
      const body = req.body;
      if (LOG_INCOMING_DELTA) {
        console.log(`Receiving delta : ${JSON.stringify(body)}`);
      }

      const delta = new Delta(req.body);

      if (!delta.inserts.length) {
        console.log(
          'Delta does not contain any insertions. Nothing should happen.',
        );
        return res.status(204).send();
      }

      const allFiles = delta
        .getInsertsFor(
          triple(
            undefined,
            new NamedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
            new NamedNode(
              'http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#FileDataObject',
            ),
          ),
        )
        .map((insert) => insert.subject.value);

      const allPhysicalFiles = allFiles.filter(
        (fileIRI) => fileIRI.slice(0, 8) === 'share://',
      );

      if (!allPhysicalFiles.length) {
        console.log(
          'No FileDataObject inserts for physical files. Nothing should happen.',
        );
        return res.status(204).send();
      }

      const physicalFiles = [...new Set(allPhysicalFiles)]; //make them unique

      console.log(
        'Physical file IRIs to be processed: ' + JSON.stringify(physicalFiles),
      );

      // The URI of the stored file uses the share:// protocol and
      // reflects the location where the file resides as a relative
      // path to the share folder. E.g. share://uploads/my-file.pdf
      // means the file is stored at /share/uploads/my-file.pdf.
      // -- https://github.com/mu-semtech/file-service/blob/v3.3.0/README.md#description
      const physicalFileIRIPrefix = /^share:\/\//;
      const physicalFilePathPrefix = '/share/';
      const physicalFilePaths = physicalFiles.map((physicalFileIRI) =>
        physicalFileIRI.replace(physicalFileIRIPrefix, physicalFilePathPrefix),
      );

      // TODO: Combine in an object.
      // TODO: Transpose structure from results > file to files > result,
      //       to allow for more details per result, e.g. viruses found.
      const filesNotFound = [];
      const filesToScan = []; // TODO: Remove, because union of the arrays below.
      const filesClean = [];
      const filesInfected = []; // TODO: Include viruses found per file.
      const filesUnableToScan = [];
      const filesOtherError = [];

      for (const file of physicalFilePaths) {
        if (!existsSync(file)) {
          console.log('File not found: ' + JSON.stringify(file));
          filesNotFound.push(file);
        } else {
          filesToScan.push(file);
          console.log('Running virus scan on file: ' + JSON.stringify(file));
          try {
            const fileScanResult = await scanFile(file);
            const fileHasVirus = fileScanResult.isInfected;
            switch (fileHasVirus) {
              case false:
                console.log('Clean');
                filesClean.push(file);
                break;
              case true:
                console.log(
                  'Infected with ' + JSON.stringify(fileScanResult.viruses),
                );
                filesInfected.push(file);
                break;
              case null:
                console.log('Unable to scan');
                filesUnableToScan.push(file);
                break;
              default:
                throw new Error('Unexpected return value from hasVirus().');
            }
          } catch (e) {
            console.warn('Other error: ' + e);
            filesOtherError.push(file);
          }
        }
      }

      console.log(
        '- Files not found by virus-scanner-service : ' +
          JSON.stringify(filesNotFound),
      );
      console.log(
        '- Files sent to clamscan JS                : ' +
          JSON.stringify(filesToScan),
      );
      console.log(
        '  - Clean                                  : ' +
          JSON.stringify(filesClean),
      );
      console.log(
        '  - Infected                               : ' +
          JSON.stringify(filesInfected),
      );
      console.log(
        '  - Unable to scan                         : ' +
          JSON.stringify(filesUnableToScan),
      );
      console.log(
        '  - Other error                            : ' +
          JSON.stringify(filesOtherError),
      );

      res.status(202).send();
    } catch (error) {
      console.log(error);
      res.status(500).send();
    }
  },
);

app.use(errorHandler);

/**
 * Scans a file for viruses.
 *
 * @async
 * @function
 * @param {String} path - Path of file to scan.
 * @returns {Object} As per clamscan 2.1.2:
 * - `file` (string) The original `filePath` passed into the `isInfected`
 *                   method.
 * - `isInfected` (boolean) **True**: File is infected;
 *                          **False**: File is clean.
 *                          **NULL**: Unable to scan.
 * - `viruses` (array) An array of any viruses found in the scanned file.
 */
async function scanFile(path) {
  const scanner = await new NodeClam().init({
    clamscan: {
      // Do not use clamscan binary because it loads database on every run.
      active: false,
    },
    clamdscan: {
      socket: '/var/run/clamav/clamd.ctl', // Unix domain socket
      host: false, // Do not connect via TCP interface
      port: false, // Do not connect via TCP interface
      localFallback: false, // Do not use local preferred binary to scan if socket/tcp fails
      active: true,
    },
    preference: 'clamdscan',
  });
  const result = await scanner.isInfected(path);
  console.log(result);
  return result;
  // For now, error handling will be the responsibility of the function caller.
}
