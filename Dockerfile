FROM semtech/mu-javascript-template:1.7.0
LABEL maintainer="info@redpencil.io"

# Install ClamAV
#
# Known errors during install that can be ignored:
# - `id: 'clamav': no such user`
#   https://bugs.debian.org/1008279
#   https://bugs.launchpad.net/ubuntu/+source/clamav/+bug/1920217
# - `invoke-rc.d: policy-rc.d denied execution of start.`
#   Intended, because service should not be started during image build.
#   https://github.com/debuerreotype/debuerreotype/blob/60b625d1ce31bd81525bb67fc3a33f9686bc3433/scripts/debuerreotype-minimizing-config#L27
#
RUN sed --in-place -e 's/^Components: main/& contrib non-free/' /etc/apt/sources.list.d/debian.sources
RUN export DEBIAN_FRONTEND=noninteractive; apt-get -y --error-on=any update && apt-get -y upgrade && apt-get -y --no-install-recommends install clamav-daemon libclamunrar clamav-testfiles-rar clamav clamdscan

# Customize ClamAV config
#
# Files exceeding the MaxFileSize, MaxScanSize, or MaxRecursion limit
# will be flagged with the virus name starting with
# "Heuristics.Limits.Exceeded".
RUN echo "AlertExceedsMax true" >> /etc/clamav/clamd.conf

VOLUME /var/lib/clamav

CMD bash app/boot-virus-scanner.sh
