import { NamedNode, triple } from 'rdflib';
import bodyParser from 'body-parser';
import { LOG_INCOMING_DELTA, LOG_INCOMING_SCAN_REQUESTS } from './config';
import {
  app,
  query, // TODO: Probably need sudo instead.
  update, // TODO: Probably need sudo instead.
  errorHandler,
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
} from 'mu';
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

      const physicalFilePaths = physicalFiles.map(filePathFromIRI);

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

/**
 * Scans a single file and stores the result.
 *
 * @param {Object} body Request body should be in JSON-format with
 *                      `file` containing a logical file IRI as a single String.
 *                      E.g. { "file": "http://mu.semte.ch/services/file-service/files/6543bc046ea4f3000e00000c" }
 * @return [201] if file was found in database and scan result stored
 *               (even if the scan failed). The stored scan result will
 *               be in response body.
 * @return [400] if request malformed.
 * @return [422] if no related physical file is found in database.
 */
app.post(
  '/scan',
  bodyParser.json({ limit: '50mb' }),
  async function (req, res) {
    try {
      const stixMalwareAnalysis = {
        started: new Date(),
        ended: undefined,
        result: 'unknown',
        resultName: undefined,
      };
      const body = req.body;
      if (LOG_INCOMING_SCAN_REQUESTS) {
        console.log(`Receiving scan request : ${JSON.stringify(body)}`);
      }

      const logicalFileIRI = body.file;
      if (
        !(
          typeof logicalFileIRI === 'string' || logicalFileIRI instanceof String
        ) ||
        !logicalFileIRI.length
      ) {
        return res.status(400).send('`file` not a non-empty String');
      }

      const physicalFileIRI = await getPhysicalFileIRI(logicalFileIRI);
      if (physicalFileIRI === null) {
        return res
          .status(422)
          .send('No physical file IRI found for: ' + logicalFileIRI);
      }

      const file = filePathFromIRI(physicalFileIRI);

      console.log({ logicalFileIRI, physicalFileIRI, file });

      if (!existsSync(file)) {
        console.log('File not found on disk: ' + JSON.stringify(file));
      } else {
        try {
          const fileScanResult = await scanFile(file);
          const fileHasVirus = fileScanResult.isInfected;
          switch (fileHasVirus) {
            case false:
              stixMalwareAnalysis.result = 'benign';
              break;
            case true:
              stixMalwareAnalysis.result = 'malicious';
              stixMalwareAnalysis.resultName = JSON.stringify(
                fileScanResult.viruses,
              );
              break;
            case null:
              console.log('clamscan JS returned null: Unable to scan');
              break;
            default:
              throw new Error('Unexpected return value from clamscan JS');
          }
        } catch (e) {
          console.log('Other error while attempting to scan: ' + e);
        }
      }
      stixMalwareAnalysis.ended = new Date();
      console.log(stixMalwareAnalysis);
      storeMalwareAnalysis(logicalFileIRI, stixMalwareAnalysis);
      console.log();
      res.status(202).send();
    } catch (e) {
      console.log(e);
      res.status(500).send('Uncaught error in /scan: ' + e);
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
  console.log('Running virus scan on file: ' + JSON.stringify(path));
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

/**
 * Gets the physical file IRI associated to a virtual/logical file IRI
 */
async function getPhysicalFileIRI(logicalFileIRI) {
  const result = await query(`
    PREFIX nie: <http://www.semanticdesktop.org/ontologies/2007/01/19/nie#>
    SELECT ?physicalFile
    WHERE {
      GRAPH ?g {
        ?physicalFile nie:dataSource ${sparqlEscapeUri(logicalFileIRI)} .
      }
    }
  `);
  if (result.results.bindings.length)
    // `[0]` is based on the assumption that, even if there are triples
    // for the logical file IRI in multiple graphs, they will all be
    // related to the same physical file IRI, so the array will always
    // only contain 1 physical file IRI.
    return result.results.bindings[0]['physicalFile'].value;
  return null;
}

/**
 * Converts a physical file IRI to a file path
 *
 * The URI of the stored file uses the share:// protocol and
 * reflects the location where the file resides as a relative
 * path to the share folder. E.g. share://uploads/my-file.pdf
 * means the file is stored at /share/uploads/my-file.pdf.
 * -- https://github.com/mu-semtech/file-service/blob/v3.3.0/README.md#description
 */
function filePathFromIRI(physicalFileIRI) {
  return physicalFileIRI.replace(/^share:\/\//, '/share/');
}

/**
 * Stores the result of a malware-scan in the database.
 *
 * @param {String} result - The malware scan result, usually one of the values
 *                          from STIX 2.1 Malware Result Vocabulary malware-result-ov:
 *                          "malicious", "suspicious", "benign" or "unknown".
 *                          https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_dtrq0daddkwa
 * @return TODO: String with id or an entire resource object?
 */
async function storeMalwareAnalysis(logicalFileIRI, stixMalwareAnalysis) {
  //PREFIX stix: <http://docs.oasis-open.org/cti/ns/stix#>
  //PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
  //INSERT {
  //GRAPH ?g {
  //<http://data.gift/virus-scanner/analysis/id/1> a stix:MalwareAnalysis;
  //mu:uuid "a-uuid-so-resource-can-render-it";
  //stix:analysis_started ${sparqlEscapeDateTime(stixMalwareAnalysis.started)}^^xsd:datetime;
  //stix:analysis_ended ${sparqlEscapeDateTime(stixMalwareAnalysis.ended)}^^xsd:datetime;
  //stix:result ${sparqlEscapeString(stixMalwareAnalysis.result)};
  //stix:sample_ref <http://logical/file>.   // or physical file IRI??
  //}
  //}
  //WHERE {
  //GRAPH ?g {
  //<share://file> a nfo:FileDataObject  // or logical file IRI ??
  //}
  //}
}
