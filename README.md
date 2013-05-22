# PlainSquare - Foursquare v2 client for mobile browsers

## Introduction

PlainSquare is a lightweight Foursquare client for both mobile and desktop web browsers. It is intended as a full-featured substitute for Foursquare Mobile. PlainSquare supports both geolocation (using device GPS or cellular / wi-fi positioning) and manual coordinate entry for phones without GPS.

PlainSquare speeds up a check-in by making this operation single-click if you do not need to shout or change your broadcast options. PlainSquare is designed to send you through as few screens as possible to do most common Foursquare tasks.

PlainSquare uses OAuth version 2 to log in to Foursquare to avoid having to store user passwords. PlainSquare supports version 2 of the Foursquare API. It is written in Python and designed for hosting on Google App Engine. 

## Installation

Before you can run PlainSquare, you have to apply for API keys at https://developer.foursquare.com/ Once you have a client ID and client secret, install those into `apikeys.yml`.

The easiest way to set it up is to run the Google App Engine Launcher and invoke the File / Add Existing Application menu item. Point it at the source code root folder. Then you can run it or deploy it to App Engine.


## Demo

See it run at: http://plainsq.appspot.com/


## Screenshots

The following screenshots show the mobile (touch-friendly) skin. On a desktop browser, the PlainSquare interface uses ordinary links instead of buttons.

This is the main menu:

![Main Menu](https://raw.github.com/mortonfox/plainsq/master/_assets/screenshots/plainsq%20-%20main.png)

