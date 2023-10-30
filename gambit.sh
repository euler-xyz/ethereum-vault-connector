#!/bin/bash

# Define the path to the test results file
GAMBIT_RESULTS_DIR="gambit_out"
TEST_RESULTS_FILE="test_results.txt"
GAMBIT_RESULTS_FILE="gambit_results.json"
TEST_DIR="test"
SRC_DIR="src"
SRC_BACKUP_DIR="src_backup"

# Delete the backup source directory and the test directory if they exist
rm -rf $SRC_BACKUP_DIR
rm -rf "$GAMBIT_RESULTS_DIR/$TEST_DIR"

# If the test results file exists, delete it
if [ -f "$GAMBIT_RESULTS_DIR/$TEST_RESULTS_FILE" ]; then
  rm "$GAMBIT_RESULTS_DIR/$TEST_RESULTS_FILE"
fi

# Create a backup of the source directory
cp -r $SRC_DIR $SRC_BACKUP_DIR

# Create a new test directory
mkdir "$GAMBIT_RESULTS_DIR/$TEST_DIR"

# Iterate over each result in the gambit results
for result in $(jq -j '.[] | @base64,"\n"' "$GAMBIT_RESULTS_DIR/$GAMBIT_RESULTS_FILE")
do
  # Decode the JSON object and extract the "name", "original", and "id" fields
  json=$(echo $result | base64 --decode)
  name=$(echo $json | jq -r '.name')
  original=$(echo $json | jq -r '.original')
  id=$(echo $json | jq -r '.id')

  # Replace the file in the source directory with the one from the gambit results
  cp "$GAMBIT_RESULTS_DIR/$name" $original

  # Run the forge test command, remove color codes, and capture the output
  output=$(gtimeout 200s bash -c "FOUNDRY_FUZZ_RUNS=10 FOUNDRY_INVARIANT_RUNS=10 forge test" | tee /dev/fd/2 | sed 's/\x1b\[[0-9;]*m//g')

  # Check if the command timed out
  if [ $? -eq 124 ]; then
    result="$id: timeout"
  else
    # Extract the number of failing tests from the output
    failing_tests=$(echo $output | grep -o 'Encountered a total of [0-9]* failing tests' | grep -o '[0-9]*')
    result="$id: $failing_tests failing tests"
  fi

  # Write the summary to a file
  echo $result >> "$GAMBIT_RESULTS_DIR/$TEST_RESULTS_FILE"
  echo $output > "$GAMBIT_RESULTS_DIR/$TEST_DIR/$id.txt"

  # Remove the source directory from the "original" path
  original=${original#$SRC_DIR/}

  # Restore the replaced file in the source directory
  cp "$SRC_BACKUP_DIR/$original" "$SRC_DIR/$original"
done

# Restore the original source directory
rm -rf $SRC_DIR
mv $SRC_BACKUP_DIR $SRC_DIR
