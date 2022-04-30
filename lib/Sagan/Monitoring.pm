package Sagan::Monitoring;

use 5.006;
use strict;
use warnings;
use JSON;
use File::Path qw(make_path);
use File::ReadBackwards;
use Carp;
use File::Slurp;
use Time::Piece;

=head1 NAME

Sagan::Monitoring - LibreNMS JSON SNMP extend and Nagios style check for Sagan stats

=head1 VERSION

Version 0.1.3

=cut

our $VERSION = '0.1.3';

=head1 SYNOPSIS

    use Sagan::Monitoring;

    my $args = {
        mode               => 'librenms',
        drop_percent_warn  => .75;
        drop_percent_crit  => 1,
        error_delta_warn   => 1,
        error_delta_crit   => 2,
        error_percent_warn => .05,
        error_percent_crit => .1,
        files=>{
               'ids'=>'/var/log/sagan/alert-ids.json',
               'foo'=>'/var/log/sagan/alert-foo.json',
               },
    };

    my $sm=Sagan::Monitoring->new( $args );
    my $returned=$sm->run;
    $sm->print;
    exit $returned->{alert};

=head1 METHODS

=head2 new

Initiate the object.

The args are taken as a hash ref. The keys are documented as below.

The only must have is 'files'.

    - mode :: Wether the print_output output should be for Nagios or LibreNMS.
      - value :: 'librenms' or 'nagios'
      - Default :: librenms
    
    - drop_percent_warn :: Drop percent warning threshold.
      - Default :: .75;
	
    - drop_percent_crit :: Drop percent critical threshold.
      - Default :: 1
	
    - files :: A hash with the keys being the instance name and the values
      being the Eve files to read. ".total" is not a valid instance name.
      Similarly anything starting with a "." should be considred reserved.

    my $args = {
        mode               => 'librenms',
        drop_percent_warn  => .75;
        drop_percent_crit  => 1,
        files=>{
               'ids'=>'/var/log/sagan/stats-ids.json',
               'foo'=>'/var/log/sagan/stats-foo.json',
               },
    };

    my $sm=Sagan::Monitoring->new( $args );

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	# init the object
	my $self = {
		'drop_percent_warn'  => '.75',
		'drop_percent_crit'  => '1',
		max_age              => 360,
		mode                 => 'librenms',
	};
	bless $self;

	# reel in the threshold values
	my @thresholds = (
		'drop_percent_warn',  'drop_percent_crit'
	);
	for my $threshold (@thresholds) {
		if ( defined( $args{$threshold} ) ) {
			$self->{$threshold} = $args{$threshold};
			if ( $args{$threshold} !~ /[0-9\.]+/ ) {
				confess( '"' . $threshold . '" with a value of "' . $args{$threshold} . '" is not numeric' );
			}
		}
	}

	# get the mode and make sure it is valid
	if (
		defined( $args{mode} )
		&& (   ( $args{mode} ne 'librenms' )
			&& ( $args{mode} ne 'nagios' ) )
		)
	{
		confess( '"' . $args{mode} . '" is not a understood mode' );
	}
	elsif ( defined( $args{mode} ) ) {
		$self->{mode} = $args{mode};
	}

	# make sure we have files specified
	if (   ( !defined( $args{files} ) )
		|| ( !defined( keys( %{ $args{files} } ) ) ) )
	{
		confess('No files specified');
	}
	else {
		$self->{files} = $args{files};
	}

	if ( defined( $self->{files}{'.total'} ) ) {
		confess('".total" is not a valid instance name');
	}

	# pull in cache dir location
	if ( !defined( $args{cache_dir} ) ) {
		$args{cache_dir} = '/var/cache/sagan-monitoring/';
	}
	$self->{cache_dir} = $args{cache_dir};

	# if the cache dir does not exist, try to create it
	if ( !-d $self->{cache_dir} ) {
		make_path( $self->{cache_dir} )
			or confess(
			'"' . $args{cache_dir} . '" does not exist or is not a directory and could not be create... ' . $@ );
	}

	return $self;
}

=head2 run

This runs it and collects the data. Also updates the cache.

This will return a LibreNMS style hash.

    my $returned=$sm->run;

=cut

sub run {
	my $self = $_[0];

	# this will be returned
	my $to_return = {
		data        => { '.total' => {} },
		version     => 1,
		error       => '0',
		errorString => '',
		alert       => '0',
		alertString => ''
	};

	my $previous;
	my $previous_file = $self->{cache_dir} . '/stats.json';
	if ( -f $previous_file ) {
		#
		eval {
			my $previous_raw = read_file($previous_file);
			$previous = decode_json($previous_raw);
		};
		if ($@) {
			$to_return->{error} = '1';
			$to_return->{errorString}
				= 'Failed to read previous JSON file, "' . $previous_file . '", and decode it... ' . $@;
			$self->{results} = $to_return;
			return $to_return;
		}
	}

	# figure out the time slot we care about
	my $from = time;
	my $till = $from - $self->{max_age};

	# process the files for each instance
	my @instances = keys( %{ $self->{files} } );
	my @alerts;
	my $current_till;
	foreach my $instance (@instances) {

		# ends processing for this file
		my $process_it = 1;

		# open the file for reading it backwards
		my $bw;
		eval {
			$bw = File::ReadBackwards->new( $self->{files}{$instance} )
				or die( 'Can not read "' . $self->{files}{$instance} . '"... ' . $! );
		};
		if ($@) {
			$to_return->{error} = '2';
			if ( $to_return->{errorString} ne '' ) {
				$to_return->{errorString} = $to_return->{errorString} . "\n";
			}
			$to_return->{errorString} = $to_return->{errorString} . $instance . ': ' . $@;
			$process_it = 0;
		}

		# get the first line, if possible
		my $line;
		if ($process_it) {
			$line = $bw->readline;
		}
		while ( $process_it
			&& defined($line) )
		{
			eval {
				my $json      = decode_json($line);
				my $timestamp = $json->{timestamp};

				# if current till is not set, set it
				if (  !defined($current_till)
					&& defined($timestamp)
					&& $timestamp =~ /^[0-9]+\-[0-9]+\-[0-9]+T[0-9]+\:[0-9]+\:[0-9\.]+[\-\+][0-9]+/ )
				{

					# get the number of hours
					my $hours = $timestamp;
					$hours =~ s/.*[\-\+]//g;
					$hours =~ s/^0//;
					$hours =~ s/[0-9][0-9]$//;

					# get the number of minutes
					my $minutes = $timestamp;
					$minutes =~ s/.*[\-\+]//g;
					$minutes =~ s/^[0-9][0-9]//;

					my $second_diff = ( $minutes * 60 ) + ( $hours * 60 * 60 );

					if ( $timestamp =~ /\+/ ) {
						$current_till = $till + $second_diff;
					}
					else {
						$current_till = $till - $second_diff;
					}
				}
				$timestamp =~ s/\..*$//;
				my $t = Time::Piece->strptime( $timestamp, '%Y-%m-%dT%H:%M:%S' );

				# stop process further lines as we've hit the oldest we care about
				if ( $t->epoch <= $current_till ) {
					$process_it = 0;
				}

				# we found the entry we are looking for if
				# this matches, so process it
				if ( defined( $json->{event_type} )
					&& $json->{event_type} eq 'stats' )
				{
					# we can stop processing now as this is what we were looking for
					$process_it = 0;

					# holds the found new alerts
					my @new_alerts;

					my $new_stats = {
    uptime             => $json->{stats}{uptime},
    c_total            => $json->{stats}{capture}{total},
    c_drop             => $json->{stats}{capture}{drop},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_threshold        => $json->{stats}{capture}{threshold},
    c_after            => $json->{stats}{capture}{after},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_alert            => $json->{stats}{capture}{alert},
    c_match            => $json->{stats}{capture}{match},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_bytes_total      => $json->{stats}{capture}{bytes_total},
    c_bytes_ignored    => $json->{stats}{capture}{bytes_ignored},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_max_bytes_line   => $json->{stats}{capture}{max_bytes_log_line},
    f_total            => $json->{stats}{flow}{total},
    f_dropped          => $json->{stats}{flow}{dropped},

						alert              => 0,
						alertString        => '',
					};

					foreach my $flow_key ( keys( %{ $json->{stats}{app_layer}{flow} } ) ) {
						my $new_key = $flow_key;
						$new_key =~ s/\-/_/g;
						$new_stats->{ 'af_' . $new_key } = $json->{stats}{app_layer}{flow}{$flow_key};
					}
					foreach my $tx_key ( keys( %{ $json->{stats}{app_layer}{tx} } ) ) {
						my $new_key = $tx_key;
						$new_key =~ s/\-/_/g;
						$new_stats->{ 'at_' . $new_key } = $json->{stats}{app_layer}{tx}{$tx_key};
					}

					# some this is a bit variable as to which will be present based on the system
					# af-packet = error
					# pcap = ifdrops
					my @zero_if_undef = ( 'errors', 'ifdropped' );
					foreach my $undef_check (@zero_if_undef) {
						if ( !defined( $new_stats->{$undef_check} ) ) {
							$new_stats->{$undef_check} = 0;
						}
					}

					# begin handling this if we have previous values
					if (   defined($previous)
						&& defined( $previous->{data}{$instance} )
						&& defined( $previous->{data}{$instance}{packets} )
						&& defined( $previous->{data}{$instance}{bytes} )
						&& defined( $previous->{data}{$instance}{dropped} ) )
					{
						# find the change for packet count
						if ( $new_stats->{packets} < $previous->{data}{$instance}{packets} ) {
							$new_stats->{packet_delta} = $new_stats->{packets};
						}
						else {
							$new_stats->{packet_delta} = $new_stats->{packets} - $previous->{data}{$instance}{packets};
						}

						# find the change for drop count
						if ( $new_stats->{dropped} < $previous->{data}{$instance}{dropped} ) {
							$new_stats->{drop_delta} = $new_stats->{dropped};
						}
						else {
							$new_stats->{drop_delta} = $new_stats->{dropped} - $previous->{data}{$instance}{dropped};
						}

						# find the percent of dropped
						if ( $new_stats->{drop_delta} != 0 ) {
							$new_stats->{drop_percent}
								= ( $new_stats->{drop_delta} / $new_stats->{packet_delta} ) * 100;
							$new_stats->{drop_percent} = sprintf( '%0.5f', $new_stats->{drop_percent} );
						}

						# check for drop percent alerts
						if (   $new_stats->{drop_percent} >= $self->{drop_percent_warn}
							&& $new_stats->{drop_percent} < $self->{drop_percent_crit} )
						{
							$new_stats->{alert} = 1;
							push( @new_alerts,
									  $instance
									. ' drop_percent warning '
									. $new_stats->{drop_percent} . ' >= '
									. $self->{drop_percent_warn} );
						}
						if ( $new_stats->{drop_percent} >= $self->{drop_percent_crit} ) {
							$new_stats->{alert} = 2;
							push( @new_alerts,
									  $instance
									. ' drop_percent critical '
									. $new_stats->{drop_percent} . ' >= '
									. $self->{drop_percent_crit} );
						}

						# check for alert status
						if ( $new_stats->{alert} > $to_return->{alert} ) {
							$to_return->{alert}       = $new_stats->{alert};
							$new_stats->{alertString} = join( "\n", @new_alerts );
							push( @alerts, @new_alerts );
						}
					}

					# add stuff to .total
					my @intance_keys = keys( %{$new_stats} );
					foreach my $total_key (@intance_keys) {
						if ( $total_key ne 'alertString' ) {
							if ( !defined( $to_return->{data}{'.total'}{$total_key} ) ) {
								$to_return->{data}{'.total'}{$total_key} = $new_stats->{$total_key};
							}
							else {
								$to_return->{data}{'.total'}{$total_key}
									= $to_return->{data}{'.total'}{$total_key} + $new_stats->{$total_key};
							}
						}
					}

					$to_return->{data}{$instance} = $new_stats;
				}

			};

			# get the next line
			$line = $bw->readline;
		}

	}

	# compute percents for .total
	if ( defined( $to_return->{data}{'.total'}{packet_delta} )
		&& ( $to_return->{data}{'.total'}{packet_delta} != 0 ) )
	{
		$to_return->{data}{'.total'}{drop_percent}
			= ( $to_return->{data}{'.total'}{drop_delta} / $to_return->{data}{'.total'}{packet_delta} ) * 100;
		$to_return->{data}{'.total'}{drop_percent} = sprintf( '%0.5f', $to_return->{data}{'.total'}{drop_percent} );

	}
	else {
		$to_return->{data}{alert} = '3';
		push( @alerts, 'Did not find a stats entry after searching back ' . $self->{max_age} . ' seconds' );
	}

	# join any found alerts into the string
	$to_return->{alertString} = join( "\n", @alerts );
	$to_return->{data}{'.total'}{alert} = $to_return->{'alert'};

	# write the cache file on out
	eval {
		my $new_cache = encode_json($to_return);
		open( my $fh, '>', $previous_file );
		print $fh $new_cache . "\n";
		close($fh);
	};
	if ($@) {
		$to_return->{error}       = '1';
		$to_return->{alert}       = '3';
		$to_return->{errorString} = 'Failed to write new cache JSON file, "' . $previous_file . '".... ' . $@;

		# set the nagious style alert stuff
		$to_return->{alert} = '3';
		if ( $to_return->{alertString} eq '' ) {
			$to_return->{alertString} = $to_return->{errorString};
		}
		else {
			$to_return->{alertString} = $to_return->{errorString} . "\n" . $to_return->{alertString};
		}
	}

	$self->{results} = $to_return;

	return $to_return;
}

=head2 print_output

Prints the output.

    $sm->print_output;

=cut

sub print_output {
	my $self = $_[0];

	if ( $self->{mode} eq 'nagios' ) {
		if ( $self->{results}{alert} eq '0' ) {
			print "OK - no alerts\n";
			return;
		}
		elsif ( $self->{results}{alert} eq '1' ) {
			print 'WARNING - ';
		}
		elsif ( $self->{results}{alert} eq '2' ) {
			print 'CRITICAL - ';
		}
		elsif ( $self->{results}{alert} eq '3' ) {
			print 'UNKNOWN - ';
		}
		my $alerts = $self->{results}{alertString};
		chomp($alerts);
		$alerts = s/\n/\, /g;
		print $alerts. "\n";
	}
	else {
		print encode_json( $self->{results} ) . "\n";
	}
}

=head1 LibreNMS HASH

    + $hash{'alert'} :: Alert status.
      - 0 :: OK
      - 1 :: WARNING
      - 2 :: CRITICAL
      - 3 :: UNKNOWN
    
    + $hash{'alertString'} :: A string describing the alert. Defaults to
      '' if there is no alert.
    
    + $hash{'error'} :: A integer representing a error. '0' represents
      everything is fine.
    
    + $hash{'errorString'} :: A string description of the error.
    
    + $hash{'data'}{$instance} :: Values migrated from the
      instance. *_delta values are created via computing the difference
      from the previously saved info. *_percent is based off of the delta
      in question over the packet delta. Delta are created for packet,
      drop, ifdrop, and error. Percents are made for drop, ifdrop, and
      error.
    
    + $hash{'data'}{'.total'} :: Total values of from all the
      intances. Any percents will be recomputed.
    

    The stat keys are migrated as below.
    
    uptime             => $json->{stats}{uptime},
    c_total            => $json->{stats}{capture}{total},
    c_drop             => $json->{stats}{capture}{drop},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_threshold        => $json->{stats}{capture}{threshold},
    c_after            => $json->{stats}{capture}{after},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_alert            => $json->{stats}{capture}{alert},
    c_match            => $json->{stats}{capture}{match},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_bytes_total      => $json->{stats}{capture}{bytes_total},
    c_bytes_ignored    => $json->{stats}{capture}{bytes_ignored},
    c_ignore           => $json->{stats}{capture}{ignore},
    c_max_bytes_line   => $json->{stats}{capture}{max_bytes_log_line},
    f_total            => $json->{stats}{flow}{total},
    f_dropped          => $json->{stats}{flow}{dropped},

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-sagan-monitoring at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Sagan-Monitoring>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Sagan::Monitoring


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Sagan-Monitoring>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Sagan-Monitoring>

=item * Search CPAN

L<https://metacpan.org/release/Sagan-Monitoring>

=back


=head * Git

L<git@github.com:VVelox/Sagan-Monitoring.git>

=item * Web

L<https://github.com/VVelox/Sagan-Monitoring>

=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Sagan::Monitoring
