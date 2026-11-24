{
  "doh": {
    "primary": "https://doh.pub/dns-query",
    "fallback": "https://cloudflare-dns.com/dns-query",
    "custom": [
      "https://223.5.5.5/dns-query"
    ]
  },
  "catalogs": {
    "ip": "https://gitee.com/mom09/hakimi/raw/master/ips.json",
    "doh": "https://gitee.com/mom09/hakimi/raw/master/doh.json",
    "ipMirrors": [],
    "dohMirrors": [],
    "timeoutSecs": 5
  },
  "proxy": {
    "mode": "pac",
    "port": 8443,
    "bind": "127.0.0.1",
    "takeover": true,
    "socksPort": 2080
  },
  "groups": [
    {
      "id": "github",
      "name": "GitHub",
      "domains": [
        {
          "pattern": "github.com"
        },
        {
          "pattern": "api.github.com"
        },
        {
          "pattern": "gist.github.com",
          "route": {
            "attempts": [
              {
                "mode": "sni",
                "sni": [
                  "api.github.com"
                ]
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "codeload.github.com"
        },
        {
          "pattern": "raw.githubusercontent.com"
        },
        {
          "pattern": "*.githubusercontent.com"
        },
        {
          "pattern": "*.githubassets.com"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "sni"
          },
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "pixiv",
      "name": "Pixiv",
      "domains": [
        {
          "pattern": "pixiv.net",
          "route": {
            "attempts": [
              {
                "mode": "ech",
                "ech": "shared"
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "www.pixiv.net",
          "route": {
            "attempts": [
              {
                "mode": "ech",
                "ech": "shared"
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "*.pixiv.net",
          "route": {
            "attempts": [
              {
                "mode": "ech",
                "ech": "shared"
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "i.pximg.net"
        },
        {
          "pattern": "s.pximg.net"
        },
        {
          "pattern": "booth.pximg.net"
        },
        {
          "pattern": "*.pximg.net"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "ech",
            "ech": "shared"
          },
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "ao3",
      "name": "AO3",
      "domains": [
        {
          "pattern": "archiveofourown.org"
        },
        {
          "pattern": "www.archiveofourown.org"
        },
        {
          "pattern": "*.archiveofourown.org"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "sni",
            "sni": [
              "",
              "archiveofourown.org."
            ]
          },
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "eh",
      "name": "E-Hentai",
      "domains": [
        {
          "pattern": "e-hentai.org"
        },
        {
          "pattern": "exhentai.org",
          "route": {
            "attempts": [
              {
                "mode": "ech",
                "ech": "shared"
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "*.e-hentai.org"
        },
        {
          "pattern": "*.exhentai.org",
          "route": {
            "attempts": [
              {
                "mode": "ech",
                "ech": "shared"
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "ehgt.org"
        },
        {
          "pattern": "*.ehgt.org"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "sni"
          },
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "hitomi",
      "name": "Hitomi",
      "domains": [
        {
          "pattern": "hitomi.la"
        },
        {
          "pattern": "*.hitomi.la"
        },
        {
          "pattern": "ltn.gold-usergeneratedcontent.net"
        },
        {
          "pattern": "*.gold-usergeneratedcontent.net"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "direct"
          },
          {
            "mode": "ech",
            "ech": "own"
          },
          {
            "mode": "sni"
          }
        ]
      }
    },
    {
      "id": "hanime",
      "name": "Hanime",
      "domains": [
        {
          "pattern": "hanime.tv"
        },
        {
          "pattern": "www.hanime.tv"
        },
        {
          "pattern": "*.hanime.tv"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "direct"
          },
          {
            "mode": "ech",
            "ech": "own"
          },
          {
            "mode": "sni"
          }
        ]
      }
    },
    {
      "id": "steam",
      "name": "Steam",
      "domains": [
        {
          "pattern": "store.steampowered.com"
        },
        {
          "pattern": "steamcommunity.com"
        },
        {
          "pattern": "*.steamcommunity.com"
        },
        {
          "pattern": "*.steampowered.com"
        },
        {
          "pattern": "*.steamstatic.com"
        },
        {
          "pattern": "steamcdn-a.akamaihd.net"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "sni"
          },
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "poipiku",
      "name": "Poipiku",
      "domains": [
        {
          "pattern": "poipiku.com",
          "route": {
            "attempts": [
              {
                "mode": "sni",
                "sni": [
                  ""
                ]
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "img.poipiku.com"
        },
        {
          "pattern": "cdn.poipiku.com"
        },
        {
          "pattern": "*.poipiku.com"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "hf",
      "name": "Hugging Face",
      "domains": [
        {
          "pattern": "huggingface.co"
        },
        {
          "pattern": "www.huggingface.co"
        },
        {
          "pattern": "*.huggingface.co"
        },
        {
          "pattern": "*.hf.co",
          "route": {
            "attempts": [
              {
                "mode": "direct"
              }
            ]
          }
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "sni",
            "sni": [
              "huggingface.co.",
              "www.huggingface.co."
            ]
          },
          {
            "mode": "direct"
          }
        ]
      }
    },
    {
      "id": "x-com",
      "name": "X-beta",
      "domains": [
        {
          "pattern": "x.com"
        },
        {
          "pattern": "*.x.com"
        },
        {
          "pattern": "t.co"
        },
        {
          "pattern": "*.twimg.com"
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "direct"
          },
          {
            "mode": "ech",
            "ech": "own"
          },
          {
            "mode": "sni"
          }
        ]
      }
    },
    {
      "id": "google",
      "name": "Google",
      "domains": [
        {
          "pattern": "www.google.com",
          "route": {
            "attempts": [
              {
                "mode": "sni",
                "sni": [
                  "www.google.com."
                ]
              },
              {
                "mode": "direct"
              }
            ]
          }
        },
        {
          "pattern": "www.google.com.hk",
          "route": {
            "attempts": [
              {
                "mode": "sni",
                "sni": [
                  "www.google.com.hk."
                ]
              },
              {
                "mode": "direct"
              }
            ]
          }
        }
      ],
      "enabled": true,
      "defaultRoute": {
        "attempts": [
          {
            "mode": "sni",
            "sni": [
              "www.google.com.",
              "www.google.com.hk."
            ]
          },
          {
            "mode": "direct"
          }
        ]
      }
    }
  ],
  "catalogVersion": 0,
  "advanced": {
    "fakeSniCandidates": [
      "www.bing.com"
    ],
    "maxCandidatesPerDomain": 8,
    "ipTimeoutMs": 2000,
    "lastGoodDays": 7,
    "planCacheSecs": 600,
    "imageRelays": [
      {
        "id": "pixiv",
        "enabled": true,
        "hosts": [
          "i.pximg.net"
        ],
        "paths": [
          "/img-original/",
          "/img-master/"
        ],
        "base": "http://127.0.0.1:8443/pximg",
        "referer": "https://www.pixiv.net/",
        "userAgent": "Piku/3.7.0",
        "fallbackDirect": true,
        "timeoutMs": 5000
      }
    ],
    "localRelay": true
  },
  "log": {
    "level": "info",
    "format": "text"
  },
  "schemaVersion": 7
}
