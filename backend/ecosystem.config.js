module.exports = {
  apps: [
    {
      name: "forensic-ml-api",
      script: "api/ml_api.py",
      cwd: __dirname,
      interpreter: "./venv/bin/python3",
      watch: false,
      env: {
        PORT: 5000
      }
    }
  ]
}


