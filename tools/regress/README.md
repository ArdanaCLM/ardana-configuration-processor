(c) Copyright 2015 Hewlett Packard Enterprise Development LP
(c) Copyright 2017-2018 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

A smarter diff tool for regression tests.

This basically does a recursive diff over an exemplar and
an output directory tree. It has a small number of plugins
that know how to diff various types of file specifically -
ini-style files, ansible group-style files, and json
and yaml, in particular.

It can be relatively smart about reporting differences:
typically the approach the tool takes is that additions
generate warnings, whereas missing or changed elements
generate errors.

