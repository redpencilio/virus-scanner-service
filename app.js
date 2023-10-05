import bodyParser from 'body-parser';
import { LOG_INCOMING_DELTA } from './config';
import { app, query, errorHandler } from 'mu';

app.get('/', function (req, res) {
  res.send('Hello from virus-scanner-service');
});

app.get('/virus-scanner/query', function (req, res) {
  var myQuery = `
    SELECT *
    WHERE {
      GRAPH <http://mu.semte.ch/graphs/public> {
        ?s ?p ?o.
      }
    }`;

  query(myQuery)
    .then(function (response) {
      res.send(JSON.stringify(response));
    })
    .catch(function (err) {
      res.send('Oops something went wrong: ' + JSON.stringify(err));
    });
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

      //await processDelta(body);

      res.status(202).send();
    } catch (error) {
      console.log(error);
      res.status(500).send();
    }
  },
);

app.use(errorHandler);
