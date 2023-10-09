// eslint-disable-next-line no-unused-vars
import { NamedNode, triple } from 'rdflib';
import bodyParser from 'body-parser';
import { LOG_INCOMING_DELTA } from './config';
import { app, query, errorHandler } from 'mu';
import { Delta } from './lib/delta';

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

      res.status(202).send();
    } catch (error) {
      console.log(error);
      res.status(500).send();
    }
  },
);

app.use(errorHandler);
