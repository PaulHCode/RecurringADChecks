# RecurringADChecks

## Overview
  This script is designed to be used as a framework for others to modify as they see fit for their environments, not as a one-size-fits-all solution.
  If you would like a more in-depth and sophisticated scan pleast contact Microsoft for an AD assessment.
  This is intended to run as a scheduled task or as part of a SCORCH runbook and has a hardcoded value.

## Requirements
- Modify the $LogFile variable to a location on the network the reports should be written to.
- If emails are desired uncomment lines 21-25 and populate the variables appropriately, also uncomment line 184.

## Modifications 
  Create new items to monitor by simply adding 2-3 lines using the same structure.
