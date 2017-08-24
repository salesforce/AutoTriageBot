# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

FROM php:7.0-apache
ADD ./vulnerablePHP/ /var/www/html/
RUN chown www-data:www-data /var/www/html/*
RUN chmod 0755 /var/www/html/.htaccess
RUN chmod +x /var/www/html/*
EXPOSE 80
