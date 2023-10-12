import { NamedNode, triple } from 'rdflib';
import bodyParser from 'body-parser';
import { LOG_INCOMING_DELTA } from './config';
import { app, query, errorHandler } from 'mu';
import { Delta } from './lib/delta';
import { existsSync } from 'node:fs';

app.get('/', function (req, res) {
  res.send('Hello from virus-scanner-service');
});

app.get('/virus-scanner/query', async function (req, res) {
  const myQuery = `
    SELECT * WHERE {
      GRAPH <http://mu.semte.ch/graphs/public> {
        ?s ?p ?o.
      }
    }`;
  try {
    const response = await query(myQuery);
    res.send(JSON.stringify(response));
  } catch (err) {
    res.send('Oops something went wrong: ' + JSON.stringify(err));
  }
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

      const filesNotFound = [];
      const filesToScan = [];
      const filesClean = [];
      const filesInfected = [];
      const filesError = [];
      physicalFilePaths.forEach(function (file) {
        if (!existsSync(file)) {
          console.warn('File not found: ' + JSON.stringify(file));
          filesNotFound.push(file);
        } else {
          filesToScan.push(file);
          console.log('Running virus scan on file: ' + JSON.stringify(file));
          // Run virus scan on file.
        }
      });

      console.log('- Files not found       : ' + JSON.stringify(filesNotFound));
      console.log('- Files sent to scanner : ' + JSON.stringify(filesToScan));
      console.log('  - Clean               : ' + JSON.stringify(filesClean));
      console.log('  - Infected            : ' + JSON.stringify(filesInfected));
      console.log('  - Other error         : ' + JSON.stringify(filesError));

      res.status(202).send();
    } catch (error) {
      console.log(error);
      res.status(500).send();
    }
  },
);

app.use(errorHandler);
