# ruff: noqa: ANN001
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "click",
#   "pymongo",
#   "python-dotenv",
#   "tabulate",
# ]
# ///

"""
Scan a MongoDB collection for top-level field coverage statistics.

USAGE EXAMPLES:
  # Basic usage with URI and collection
  python mfields.py --mongouri mongodb://localhost:27017/mydb --collection users

  # Analyze ALL collections in the database
  python mfields.py --mongouri mongodb://localhost:27017/mydb

  # Using short flags and custom sample size
  python mfields.py -c products -n 5000 --mongouri $MONGO_URI

  # Sort fields alphabetically by name
  python mfields.py -c orders --sort name --mongouri mongodb://localhost:27017/mydb

  # Sort by percentage (default) with explicit option
  python mfields.py -c customers --sort perc --mongouri mongodb://localhost:27017/mydb

  # Using environment variable for MongoDB URI
  export MONGO_URI=mongodb://localhost:27017/mydb
  python mfields.py -c inventory -n 2000 --sort name

  # Analyze all collections with custom settings
  python mfields.py -n 500 --sort name --mongouri $MONGO_URI

  # Output as JSON for version control
  python mfields.py --mongouri $MONGO_URI --format json > field_analysis.json

Will print a table of top-level fields, the count, and % presence in the sample.
"""

import json
import os
import sys
from collections import Counter

import click
import pymongo
from dotenv import load_dotenv
from tabulate import tabulate


def get_field_statistics(db, collection, sample_size=1000, sort_by='perc'):
    """
    Samples `sample_size` documents from `collection` and counts top-level field presence.
    Returns a list of (field, count, percent), plus the actual n_docs found.

    Args:
        db: MongoDB database object
        collection: Collection name to analyze
        sample_size: Number of documents to sample
        sort_by: 'perc' for percentage then name, 'name' for alphabetical
    """
    pipeline = [{'$sample': {'size': sample_size}}]
    cursor = db[collection].aggregate(pipeline)

    counter = Counter()
    n_docs = 0

    for doc in cursor:
        n_docs += 1
        keys = set(doc.keys()) - {'_id'}  # omit _id if you like
        counter.update(keys)

    if n_docs == 0:
        return [], 0

    stats = []
    for field, count in counter.items():
        percentage = round(100.0 * count / n_docs, 1)
        stats.append((field, count, percentage))

    # Sort based on the sort_by parameter
    if sort_by.lower() == 'name':
        # Sort alphabetically by field name
        stats.sort(key=lambda x: x[0])
    else:  # sort_by == 'perc'
        # Sort by percentage (descending), then by field name (ascending)
        stats.sort(key=lambda x: (-x[1], x[0]))

    return stats, n_docs


def format_output(collection_results, output_format, sample_size, sort_by):
    """Format the results according to the specified output format."""

    if output_format == 'json':
        # Create JSON structure
        result = {
            'metadata': {
                'sample_size': sample_size,
                'sort_by': sort_by,
            },
            'collections': {},
        }

        for collection_name, stats, n_docs in collection_results:
            result['collections'][collection_name] = {
                'documents_sampled': n_docs,
                'fields': [
                    {'name': field, 'count': count, 'percentage': percentage} for field, count, percentage in stats
                ],
            }

        print(json.dumps(result, indent=4, sort_keys=True))

    else:  # table format
        for collection_name, stats, n_docs in collection_results:
            headers = ['Field', 'Count', '% Presence']
            table_stats = [(field, count, f'{percentage}%') for field, count, percentage in stats]

            click.secho(
                f'\nTop-level field coverage in `{collection_name}` (sampled {n_docs} docs):', fg='cyan', bold=True
            )
            print(tabulate(table_stats, headers=headers, tablefmt='psql'))


@click.command()
@click.option(
    '--mongouri',
    type=str,
    help='MongoDB URI (with database)',
    required=True,
)
@click.option(
    '--collection',
    '-c',
    type=str,
    help='Collection to scan (if not provided, scans all collections)',
    required=False,
)
@click.option(
    '--sample-size',
    '-n',
    type=int,
    default=1000,
    show_default=True,
    help='Number of documents to sample (random).',
)
@click.option(
    '--sort',
    type=click.Choice(['name', 'perc'], case_sensitive=False),
    default='perc',
    show_default=True,
    help='Sort fields by name or percentage (perc).',
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['table', 'json'], case_sensitive=False),
    default='table',
    show_default=True,
    help='Output format (table or json).',
)
def main(mongouri, collection, sample_size, sort, format) -> None:
    """Connect to MongoDB and show top-level field coverage for a sampled subset of a collection.

    This tool helps analyze MongoDB collections by sampling documents and showing:
    - Which fields exist in the collection
    - How many documents contain each field
    - The percentage coverage of each field

    EXAMPLES:

    Basic usage:
        python mfields.py --mongouri mongodb://localhost:27017/mydb --collection users

    Analyze ALL collections in database:
        python mfields.py --mongouri mongodb://localhost:27017/mydb

    Custom sample size and sorting:
        python mfields.py -c products -n 5000 --sort name --mongouri $MONGO_URI

    Using environment variables:
        export MONGO_URI=mongodb://localhost:27017/mydb
        python mfields.py -c orders --sort perc

    Analyze all collections with custom settings:
        python mfields.py -n 500 --sort name --mongouri $MONGO_URI

    JSON output for version control:
        python mfields.py --mongouri $MONGO_URI --format json > field_analysis.json
        python mfields.py -c users --format json --sort name > users_fields.json

    SORTING OPTIONS:
    - 'perc' (default): Sort by field coverage percentage (highest first), then alphabetically
    - 'name': Sort fields alphabetically by name

    OUTPUT FORMATS:
    - 'table' (default): Human-readable table format with colors
    - 'json': Machine-readable JSON format with metadata (ideal for version control)
    """

    if not mongouri:
        load_dotenv()
        mongouri = os.environ.get('MONGO_URI')
    if not mongouri:
        click.secho('Error: No MongoDB URI provided and MONGO_URI env var not set.', fg='red')
        sys.exit(1)

    try:
        cl = pymongo.MongoClient(mongouri)
        cl.admin.command('ping')
        db = cl.get_default_database()
    except Exception as exc:  # noqa: BLE001
        click.secho(f'Could not connect to MongoDB: {exc}', fg='red')
        sys.exit(2)

    collection_results = []

    collections_to_process = sorted(db.list_collection_names() if not collection else [collection])
    if not collections_to_process:
        click.secho('No collections found in database!', fg='red', err=True)
        sys.exit(1)

    for coll_name in collections_to_process:
        stats, n_docs = get_field_statistics(db, coll_name, sample_size, sort)
        if n_docs == 0:
            if format == 'table':
                click.secho(f'No documents found in `{coll_name}` - skipping', fg='yellow', err=True)
            continue

        collection_results.append((coll_name, stats, n_docs))

    format_output(collection_results, format, sample_size, sort)


if __name__ == '__main__':
    main()
