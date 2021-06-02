exports.getSuccessTemplate = (message1, message2) => {
  return `<html>

<head>
  <link href="https://fonts.googleapis.com/css?family=Nunito+Sans:400,400i,700,900&display=swap" rel="stylesheet">
</head>
<style>
  body {
    text-align: center;
    padding: 40px 0;
    background-image: linear-gradient(109.6deg, #fed6e3 11.2%, #a8edea 91.2%);
  }

  h1 {
    color: #00c853;
    font-family: "Nunito Sans", "Helvetica Neue", sans-serif;
    font-weight: 900;
    font-size: 40px;
    margin-bottom: 10px;
  }

  p {
    color: #404F5E;
    font-family: "Nunito Sans", "Helvetica Neue", sans-serif;
    font-size: 20px;
    margin: 0;
  }

  i {
    color: #00c853;
    font-size: 150px;
    line-height: 300px;
    margin-left: -15px;
  }

  .card {
    background: rgba(255, 255, 255, 0.2);
    padding: 60px;
    border-radius: 4px;
    box-shadow: 0 2px 3px #C8D0D8;
    display: inline-block;
    margin: 0 auto;
  }
</style>

<body>
  <div class="card">
    <div style="border-radius:200px; height:300px; width:300px; border-style: solid; border-color: #00c853; margin:0 auto;">
      <i class="checkmark">✓</i>
    </div>
    <h1>Success</h1>
    <p>${message1}<br /> ${message2}</p>
  </div>
</body>

</html>`;
}

exports.getFailedTemplate = (message1, message2) => {
  return `<html>

<head>
  <link href="https://fonts.googleapis.com/css?family=Nunito+Sans:400,400i,700,900&display=swap" rel="stylesheet">
</head>
<style>
  body {
    text-align: center;
    padding: 40px 0;
    background-image: linear-gradient(109.6deg, #fed6e3 11.2%, #a8edea 91.2%);
  }

  h1 {
    color: #ff1744;
    font-family: "Nunito Sans", "Helvetica Neue", sans-serif;
    font-weight: 900;
    font-size: 40px;
    margin-bottom: 10px;
  }

  p {
    color: #404F5E;
    font-family: "Nunito Sans", "Helvetica Neue", sans-serif;
    font-size: 20px;
    margin: 0;
  }

  i {
    color: #ff1744;
    font-size: 150px;
    line-height: 300px;
    margin-left: -15px;
  }

  .card {
    background: rgba(255, 255, 255, 0.2);
    padding: 60px;
    border-radius: 4px;
    box-shadow: 0 2px 3px #C8D0D8;
    display: inline-block;
    margin: 0 auto;
  }
</style>

<body>
  <div class="card">
    <div style="border-radius:200px; height:300px; width:300px; border-style: solid; border-color: #ff1744; margin:0 auto;">
      <i class="checkmark">✕</i>
    </div>
    <h1>Error</h1>
    <p>${message1}<br /> ${message2}</p>
  </div>
</body>

</html>`;
}