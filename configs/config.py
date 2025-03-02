REGISTER_MODE = False
FARM_MODE = True

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃     REFERRAL TIMING    ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# The time that referrals will be registering

DAYS = 0
HOURS = 0
MINUTES = 10

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃   DELAY BEFORE START   ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# The time in seconds the account will wait before process, 60 * 60 = 1 hour

MIN_DELAY_BEFORE_START = 0
MAX_DELAY_BEFORE_START = 12 * 60 * 60

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ SSL CERTIFICATE VERIFY ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# False only if error: SSLCertVerificationError: (1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed

SSL = True

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃      TASKS CONFIG      ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# Enable or disable tasks

DO_PROOF = True                         # Send proof
DO_SUBMIT_PROOF_TASK = True             # Complete the task with proof confirmation
DO_LIGHT_NODE_RUN_TASK = True           # Complete the task with light node confirmation
DO_PLEDGE_PASS_HOLD_TASK = False        # Complete the task with free pass
DO_OG_PLEDGE_PASS_HOLD_TASK = False     # Complete the task with OG pass

# ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃      MINT PASSES       ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━┛
# Enable or disable tasks

MINT_FREE_PASS = True                   # Mint free pledge pass. Need ETH to pay transaction fees
MINT_OG_PASS = False                    # Mint OG pledge pass for 0.0009 ETH