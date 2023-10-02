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

app.use(errorHandler);
