#!/bin/bash

while getopts b:d: flag
do
    case "${flag}" in
        b) buildNum=${OPTARG};;
        d) dbUrl=${OPTARG};;
    esac
done

BUILD_NUMBER=$buildNum
DATABASE_URL=$dbUrl
docker-compose up -d --build