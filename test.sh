curl -X POST -H "Content-Type: application/json" -d '{
  "expirationTime": "2021-05-19T12:34:56Z",
  "dgc": {
    "ver": "1.0.0",
    "nam": {
      "fn": "Achternaam en naam",
      "fnt": "ACHTERNAAM<EN<NAAM",
      "gn": "Voor Naam",
      "gnt": "VOOR<NAAM"
    },
    "dob": "1953-09-03",
    "v": [
      {
        "tg": "840539006",
        "vp": "1119349007",
        "mp": "BBIBP-CorV",
        "ma": "",
        "dn": 8,
        "sd": 8,
        "dt": "2021-02-18",
        "co": "",
        "is": "Ministry of Health Welfare and Sport",
        "ci": "urn:uvci:01:NL:33385024475e4c56a17b749f92404039"
        }
    ]
  }
}' http://localhost:4002/get_credential
